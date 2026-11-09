// PRAETOR/1 benchmark harness. Measures real work on this machine; no
// extrapolated numbers are reported anywhere in the docs.
import process from 'node:process';
import {
  SecureChannel,
  SealKey,
  clientFinish,
  clientInit,
  generateServerKeypair,
  kemDecapsulate as decapsulate,
  kemEncapsulate as encapsulate,
  kemKeygen,
  randomBytes,
  serverFinish,
  serverRespond,
  psealOpen,
} from '../src/index.js';

const MIB = 1024 * 1024;

function measure(fn, bytes, minMs) {
  // Warm up JIT and caches.
  for (let i = 0; i < 3; i += 1) fn();
  const start = process.hrtime.bigint();
  let iters = 0;
  let elapsed = 0;
  while (elapsed < minMs * 1e6) {
    fn();
    iters += 1;
    elapsed = Number(process.hrtime.bigint() - start);
  }
  const seconds = elapsed / 1e9;
  return { iters, seconds, mibPerSec: (bytes * iters) / seconds / MIB, opsPerSec: iters / seconds };
}

export function runBench({ json = false, quick = false } = {}) {
  const key = new SealKey(randomBytes(32));
  const rows = [];
  const sizes = quick ? [64, 1024, 65536] : [64, 1024, 65536, MIB];

  for (const size of sizes) {
    const pt = randomBytes(size);
    const aad = Buffer.from('bench');
    const env = key.seal(pt, aad);
    const minMs = quick ? 120 : 300;
    const enc = measure(() => key.seal(pt, aad), size, minMs);
    const dec = measure(() => key.open(env, aad), size, minMs);
    rows.push({
      op: 'pseal.seal',
      size,
      mibPerSec: enc.mibPerSec,
      opsPerSec: enc.opsPerSec,
      usPerOp: (enc.seconds / enc.iters) * 1e6,
    });
    rows.push({
      op: 'pseal.open',
      size,
      mibPerSec: dec.mibPerSec,
      opsPerSec: dec.opsPerSec,
      usPerOp: (dec.seconds / dec.iters) * 1e6,
    });
  }

  // Fixed-cell channel: 1 KiB payload in a 1 KiB cell.
  const chainA = randomBytes(32);
  const chainB = randomBytes(32);
  const a = new SecureChannel({ sendChain: chainA, recvChain: chainB, cellSize: 1024 });
  const b = new SecureChannel({ sendChain: chainB, recvChain: chainA, cellSize: 1024 });
  const payload = randomBytes(1008);
  const cell = measure(
    () => {
      const [c] = a.send(payload);
      b.receive(c);
    },
    1008,
    quick ? 150 : 400,
  );
  rows.push({
    op: 'wire.cell.roundtrip',
    size: 1008,
    mibPerSec: cell.mibPerSec,
    opsPerSec: cell.opsPerSec,
    usPerOp: (cell.seconds / cell.iters) * 1e6,
  });

  // Hybrid KEM.
  const kp = kemKeygen();
  const kem = measure(
    () => {
      const e = encapsulate(kp.publicKey);
      decapsulate(e.cipherText, kp.secretKey);
    },
    0,
    quick ? 300 : 800,
  );
  rows.push({
    op: 'kem.xwing.encap+decap',
    size: 0,
    mibPerSec: 0,
    opsPerSec: kem.opsPerSec,
    usPerOp: (kem.seconds / kem.iters) * 1e6,
  });

  // Full handshake.
  const server = generateServerKeypair();
  const hs = measure(
    () => {
      const c = clientInit(server.publicKey);
      const s = serverRespond(server.secretKey, c.message);
      const cf = clientFinish(c.state, s.reply);
      serverFinish(s.state, cf.confirm);
    },
    0,
    quick ? 400 : 900,
  );
  rows.push({
    op: 'handshake.full',
    size: 0,
    mibPerSec: 0,
    opsPerSec: hs.opsPerSec,
    usPerOp: (hs.seconds / hs.iters) * 1e6,
  });

  if (json) {
    process.stdout.write(`${JSON.stringify({ ok: true, node: process.version, rows }, null, 2)}\n`);
    return rows;
  }

  process.stdout.write(`PRAETOR/1 benchmark — node ${process.version}, ${process.arch}\n`);
  process.stdout.write(
    `${'operation'.padEnd(24)}${'bytes'.padStart(9)}${'MiB/s'.padStart(11)}${'ops/s'.padStart(12)}${'µs/op'.padStart(11)}\n`,
  );
  for (const r of rows) {
    process.stdout.write(
      `${r.op.padEnd(24)}${String(r.size).padStart(9)}${r.mibPerSec.toFixed(1).padStart(11)}${r.opsPerSec.toFixed(0).padStart(12)}${r.usPerOp.toFixed(1).padStart(11)}\n`,
    );
  }
  process.stdout.write(
    '\nNotes: single process, single thread, no pipelining. pseal includes two passes\n' +
      '(SIV prefix + AEAD) and 80 B overhead. Cell figures include fragmentation,\n' +
      'sealing, authentication and reassembly end to end.\n',
  );
  return rows;
}

const isMain = process.argv[1]?.endsWith('bench.js');
if (isMain) runBench({ json: process.argv.includes('--json'), quick: process.argv.includes('--quick') });
