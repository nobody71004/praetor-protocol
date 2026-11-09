#!/usr/bin/env node
// VANTA/1 command line interface.
//
// Designed for both humans and automated agents:
//   * every command supports --json with a stable schema;
//   * key material is written to files, never echoed, unless explicitly asked;
//   * exit codes are stable: 0 ok, 2 usage, 3 authentication, 4 policy.
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { basename, join } from 'node:path';
import process from 'node:process';
import {
  DEFAULT_CELL_SIZE,
  ERR,
  Keyring,
  SealKey,
  VantaError,
  concat,
  decryptBuffer,
  decryptFileSync,
  encryptBuffer,
  encryptFileSync,
  fromBase64,
  fromHex,
  hex,
  kemDecapsulate,
  kemEncapsulate,
  kemKeygen,
  padme,
  randomBytes,
  shamirCombine,
  shamirSplit,
  toBase64,
  vsealOpen,
  vsealSeal,
  wipe,
} from '../src/index.js';

const [, , command, ...rest] = process.argv;
const args = parseArgs(rest);

function parseArgs(argv) {
  const flags = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const body = a.slice(2);
      const eq = body.indexOf('=');
      if (eq >= 0) {
        flags[body.slice(0, eq)] = body.slice(eq + 1);
      } else if (argv[i + 1] !== undefined && !argv[i + 1].startsWith('--')) {
        flags[body] = argv[++i];
      } else {
        flags[body] = true;
      }
    } else {
      flags._.push(a);
    }
  }
  return flags;
}

function out(obj) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
}

function die(err) {
  const code =
    err instanceof VantaError
      ? err.code === ERR.AUTH
        ? 3
        : err.code === ERR.POLICY || err.code === ERR.KEY
          ? 4
          : 2
      : 2;
  if (args.json) {
    process.stdout.write(
      `${JSON.stringify({ ok: false, error: err.code ?? 'ERROR', message: err.message })}\n`,
    );
  } else {
    process.stderr.write(`vanta: ${err.message}\n`);
  }
  process.exit(code);
}

function readInput() {
  if (args.in !== undefined) return readFileSync(args.in);
  return readFileSync(0);
}

function writeOutput(buf) {
  if (args.out !== undefined) {
    writeFileSync(args.out, buf);
    return { written: args.out, bytes: buf.length };
  }
  process.stdout.write(buf);
  return { written: 'stdout', bytes: buf.length };
}

function loadKey() {
  if (args['key-hex']) return fromHex(args['key-hex'], 'key');
  const path = args.key;
  if (!path) throw new VantaError(ERR.KEY, 'provide --key <file> or --key-hex <64 hex chars>');
  if (!existsSync(path)) throw new VantaError(ERR.KEY, `key file not found: ${path}`);
  const raw = readFileSync(path);
  if (raw.length === 32) return raw; // raw key file
  let parsed;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    throw new VantaError(ERR.KEY, 'key file is neither 32 raw bytes nor JSON');
  }
  const key = fromBase64(parsed.key, 'key');
  if (key.length !== 32) throw new VantaError(ERR.KEY, 'key must be 32 bytes');
  return key;
}

function publicHeader(h) {
  return {
    version: h.version,
    suite: h.suite,
    chunkSize: h.chunkSize,
    totalSize: h.totalSize,
    realSize: h.realSize,
    flags: h.flags,
    name: h.name.toString('utf8'),
  };
}

function saveKey(path, key) {
  const json = JSON.stringify({ version: 1, suite: 'VANTA/1', key: toBase64(key) }, null, 2);
  writeFileSync(path, `${json}\n`, { mode: 0o600 });
  return path;
}

const commands = {
  keygen() {
    const key = randomBytes(32);
    if (args.stdout) {
      // Deliberately explicit: printing keys to a terminal is unsafe.
      process.stdout.write(`${toBase64(key)}\n`);
      return;
    }
    const path = args.out ?? 'vanta.key';
    saveKey(path, key);
    if (args.json) out({ ok: true, keyFile: path, keyBytes: 32, note: 'key written with mode 0600' });
    else process.stdout.write(`wrote ${path} (keep it offline, mode 0600)\n`);
  },

  seal() {
    const key = loadKey();
    const pt = readInput();
    const aad = args.aad ?? '';
    let body = pt;
    let padded = false;
    if (args.pad !== undefined) {
      // The length frame makes padding reversible; without it the receiver
      // cannot distinguish padding from plaintext.
      const target = padme(pt.length + 4, Number(args.pad));
      body = Buffer.alloc(target);
      body.writeUInt32BE(pt.length, 0);
      pt.copy(body, 4);
      randomBytes(target - 4 - pt.length).copy(body, 4 + pt.length);
      padded = true;
    }
    const env = vsealSeal(key, body, aad, { deterministic: args.deterministic === true });
    const w = writeOutput(env);
    if (args.json) {
      out({
        ok: true,
        ...w,
        plaintextBytes: pt.length,
        envelopeBytes: env.length,
        overhead: env.length - pt.length,
        padded,
        aad: Boolean(aad),
      });
    }
  },

  open() {
    const key = loadKey();
    const env = readInput();
    let pt = vsealOpen(key, env, args.aad ?? '', { deterministic: args.deterministic === true });
    if (args.pad) {
      if (pt.length < 4) throw new VantaError(ERR.MALFORMED, 'padded plaintext is too short');
      const n = pt.readUInt32BE(0);
      if (n > pt.length - 4) throw new VantaError(ERR.MALFORMED, 'padded length out of range');
      pt = pt.subarray(4, 4 + n);
    }
    const w = writeOutput(pt);
    if (args.json) out({ ok: true, ...w });
  },

  encrypt() {
    const key = loadKey();
    if (args.in !== undefined && args.out !== undefined) {
      const meta = encryptFileSync(args.in, args.out, key, {
        chunkSize: args.chunk ? Number(args.chunk) : undefined,
        padTo: args.pad ? Number(args.pad) : undefined,
        name: args.name,
      });
      if (args.json) out({ ok: true, ...meta, salt: toBase64(meta.salt), out: args.out });
      else process.stdout.write(`encrypted ${args.in} -> ${args.out}\n`);
      return;
    }
    const ct = encryptBuffer(readInput(), key, {
      chunkSize: args.chunk ? Number(args.chunk) : undefined,
      padTo: args.pad ? Number(args.pad) : undefined,
      name: args.name,
    });
    const w = writeOutput(ct);
    if (args.json) out({ ok: true, ...w });
  },

  decrypt() {
    const key = loadKey();
    if (args.in !== undefined && args.out !== undefined) {
      const meta = decryptFileSync(args.in, args.out, key);
      if (args.json) {
        out({ ok: true, ...meta, header: publicHeader(meta.header), out: args.out });
      }
      else process.stdout.write(`decrypted ${args.in} -> ${args.out}\n`);
      return;
    }
    const { plaintext, header } = decryptBuffer(readInput(), key);
    const w = writeOutput(plaintext);
    if (args.json) out({ ok: true, ...w, headerBytes: header.totalSize });
  },

  split() {
    const key = loadKey();
    const n = Number(args.n ?? 5);
    const k = Number(args.k ?? 3);
    const dir = args.out ?? '.';
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const shares = shamirSplit(key, n, k);
    const paths = shares.map((share, i) => {
      const p = join(dir, `${args.prefix ?? 'vanta'}.${i + 1}.share`);
      writeFileSync(p, `${toBase64(share)}\n`, { mode: 0o600 });
      return p;
    });
    if (args.json) out({ ok: true, n, k, shares: paths });
    else process.stdout.write(`wrote ${n} shares (threshold ${k}) to ${dir}\n`);
  },

  combine() {
    const list = String(args.shares ?? '')
      .split(',')
      .filter(Boolean)
      .map((p) => fromBase64(readFileSync(p, 'utf8').trim(), 'share'));
    if (list.length < 2) throw new VantaError(ERR.POLICY, 'provide --shares a.share,b.share,...');
    const key = shamirCombine(list);
    if (args.out) {
      saveKey(args.out, key);
      if (args.json) out({ ok: true, keyFile: args.out });
    } else if (args.stdout) {
      process.stdout.write(`${toBase64(key)}\n`);
    } else {
      out({ ok: true, keyHex: hex(key), warning: 'key printed; prefer --out <file>' });
    }
    wipe(key);
  },

  manifest() {
    out(manifest());
  },

  selftest() {
    const results = [];
    const check = (name, fn) => {
      const t0 = process.hrtime.bigint();
      try {
        fn();
        results.push({ name, ok: true, ms: Number(process.hrtime.bigint() - t0) / 1e6 });
      } catch (err) {
        results.push({ name, ok: false, error: err.message });
      }
    };
    const key = randomBytes(32);
    const pt = randomBytes(4096);
    const aad = Buffer.from('selftest');
    const env = vsealSeal(key, pt, aad);
    check('vseal.roundtrip', () => {
      if (!Buffer.from(vsealOpen(key, env, aad)).equals(pt)) throw new Error('mismatch');
    });
    check('vseal.tamper', () => {
      const bad = Buffer.from(env);
      bad[200] ^= 1;
      try {
        vsealOpen(key, bad, aad);
        throw new Error('tampered envelope accepted');
      } catch (e) {
        if (e.code !== ERR.AUTH) throw e;
      }
    });
    check('container.roundtrip', () => {
      const ct = encryptBuffer(pt, key, { chunkSize: 1024 });
      const { plaintext } = decryptBuffer(ct, key);
      if (!plaintext.equals(pt)) throw new Error('mismatch');
    });
    check('kem.roundtrip', () => {
      const kp = kemKeygen();
      const e = kemEncapsulate(kp.publicKey);
      if (!Buffer.from(kemDecapsulate(e.cipherText, kp.secretKey)).equals(e.sharedSecret)) {
        throw new Error('mismatch');
      }
    });
    check('guard.purpose-binding', () => {
      const kr = new Keyring({ now: () => 1 });
      kr.add('x', randomBytes(32), { purposes: ['a'] });
      const e = kr.seal('x', Buffer.from('data'), { purpose: 'a' });
      try {
        kr.open('x', e, { purpose: 'b' });
        throw new Error('purpose bypass');
      } catch (err) {
        if (err.code !== ERR.POLICY) throw err;
      }
    });
    const ok = results.every((r) => r.ok);
    if (args.json) out({ ok, results });
    else {
      for (const r of results) {
        process.stdout.write(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.ok ? '' : ` — ${r.error}`}\n`);
      }
      process.stdout.write(ok ? 'selftest: PASS\n' : 'selftest: FAIL\n');
    }
    if (!ok) process.exit(1);
  },

  async bench() {
    const { runBench } = await import('../bench/bench.js');
    runBench({ json: Boolean(args.json), quick: Boolean(args.quick) });
  },

  stats() {
    const p = args.key;
    if (!p) throw new VantaError(ERR.POLICY, 'provide --key <file>');
    out({ ok: true, bytes: statSync(p).size, file: basename(p) });
  },

  help() {
    process.stdout.write(`VANTA/1 — sealed envelopes, hybrid PQ handshake, fixed-cell obfuscation

  vanta keygen   --out vanta.key [--stdout]
  vanta seal     --key vanta.key [--in f] [--out f] [--aad s] [--pad M] [--json]
  vanta open     --key vanta.key [--in f] [--out f] [--aad s] [--json]
  vanta encrypt  --key vanta.key --in f --out f.vanta [--chunk N] [--pad M]
  vanta decrypt  --key vanta.key --in f.vanta --out f
  vanta split    --key vanta.key --n 5 --k 3 --out dir [--prefix vanta]
  vanta combine  --shares a.share,b.share,c.share --out vanta.key
  vanta selftest [--json]
  vanta bench    [--json] [--quick]
  vanta manifest

Numbers: cell 1024 B, envelope overhead 80 B, Padmé padding <= +12%.
`);
  },
};

function manifest() {
  return {
    protocol: 'VANTA/1',
    status: 'reference-implementation / not externally audited',
    suites: {
      aead: 'VSEAL/1 (HMAC-SHA-256 SIV + ChaCha20-Poly1305 + committing tag)',
      kem: 'VANTA-KEM/1 (X-Wing structure over X25519 + ML-KEM-768)',
      hash: 'SHA-256 / SHA3-256',
    },
    guarantees: [
      'IND-CPA and INT-CTXT under ChaCha20-Poly1305',
      'nonce-misuse resistance (SIV): caller nonce reuse leaks only equality',
      'key-committing ciphertexts',
      'no cleartext version/magic/length in wire cells',
      'replay, reorder, truncation and chunk-splice detection',
      'hybrid post-quantum key establishment with forward secrecy',
      'per-epoch symmetric ratchet with key erasure',
    ],
    limits: {
      envelopeOverheadBytes: 80,
      deterministicOverheadBytes: 64,
      defaultCellSize: DEFAULT_CELL_SIZE,
      cellOverheadBytes: 80,
      maxCellSize: 65519,
      padmeMaxOverheadPct: 12,
      keyBytes: 32,
    },
    commands: [
      { name: 'keygen', args: ['--out', '--stdout'], output: 'key file (0600) or base64' },
      { name: 'seal', args: ['--key', '--in', '--out', '--aad', '--pad', '--json'] },
      { name: 'open', args: ['--key', '--in', '--out', '--aad', '--json'] },
      { name: 'encrypt', args: ['--key', '--in', '--out', '--chunk', '--pad'] },
      { name: 'decrypt', args: ['--key', '--in', '--out'] },
      { name: 'split', args: ['--key', '--n', '--k', '--out', '--prefix'] },
      { name: 'combine', args: ['--shares', '--out'] },
      { name: 'selftest', args: ['--json'] },
      { name: 'bench', args: ['--json', '--quick'] },
    ],
    agentPolicy: {
      keyExposure: 'never return raw keys to a model; pass capability ids',
      dangerousOps: ['keygen --stdout', 'combine --stdout'],
      recommended: 'wrap CLI in Keyring with purpose-scoped capabilities and audit logging',
    },
  };
}

const fn = commands[command ?? 'help'];
if (!fn) die(new VantaError(ERR.POLICY, `unknown command: ${command}`));
Promise.resolve()
  .then(fn)
  .catch(die);
