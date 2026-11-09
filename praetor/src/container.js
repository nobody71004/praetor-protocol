// PRAETOR/CONTAINER — padded, authenticated file container.
//
// Layout (opaque mode: no magic, no cleartext structure):
//   salt(16) || u32 headerLen || headerEnvelope || (u32 chunkLen || chunkEnvelope)*
//
// The salt makes passphrase-derived keys unique per file. The header and every
// chunk are PSEAL envelopes; chunk AAD binds the chunk index and the final
// flag, so chunks cannot be reordered, dropped, duplicated, or truncated
// without detection. Ciphertext length is the Padmé-padded length of the
// plaintext plus a constant envelope overhead.
import { Buffer } from 'node:buffer';
import {
  closeSync,
  openSync,
  readSync,
  writeSync,
  fstatSync,
  fsyncSync,
  renameSync,
  unlinkSync,
} from 'node:fs';
import { SealKey } from './aead.js';
import { padme } from './padme.js';
import {
  EMPTY,
  ERR,
  PraetorError,
  assert,
  concat,
  ctEqual,
  randomBytes,
  readU32,
  scryptKey,
  sha256,
  toBytes,
  u16be,
  u32be,
  u64be,
} from './util.js';

const LABEL_HEADER = Buffer.from('PRAETOR/1/file/header');
const LABEL_CHUNK = Buffer.from('PRAETOR/1/file/chunk');
const LABEL_NAME = Buffer.from('PRAETOR/1/file/name');

export const DEFAULT_CHUNK_SIZE = 1 << 20;
export const HEADER_PLAIN_BYTES = 30;
export const CONTAINER_VERSION = 1;

export function keyFromPassphrase(passphrase, salt, params) {
  return scryptKey(passphrase, salt, params);
}

function buildHeader({ chunkSize, totalSize, realSize, flags = 0, name = EMPTY }) {
  const nm = toBytes(name);
  assert(nm.length <= 0xffff, ERR.RANGE, 'file name too long');
  const head = Buffer.allocUnsafe(HEADER_PLAIN_BYTES);
  head.writeUInt8(CONTAINER_VERSION, 0);
  head.writeUInt8(1, 1); // suite: PSEAL/1
  head.writeUInt16BE(0, 2);
  head.writeUInt32BE(chunkSize, 4);
  head.writeBigUInt64BE(BigInt(totalSize), 8);
  head.writeBigUInt64BE(BigInt(realSize), 16);
  head.writeUInt32BE(flags, 24);
  head.writeUInt16BE(nm.length, 28);
  return concat(head, nm);
}

function parseHeader(plain) {
  const pt = toBytes(plain);
  assert(pt.length >= HEADER_PLAIN_BYTES, ERR.MALFORMED, 'file header truncated');
  const version = pt.readUInt8(0);
  assert(version === CONTAINER_VERSION, ERR.VERSION, `unsupported container version ${version}`);
  const suite = pt.readUInt8(1);
  assert(suite === 1, ERR.VERSION, 'unsupported container suite');
  const chunkSize = readU32(pt, 4);
  const totalSize = readU64Safe(pt, 8);
  const realSize = readU64Safe(pt, 16);
  const flags = readU32(pt, 24);
  const nameLen = pt.readUInt16BE(28);
  assert(pt.length >= HEADER_PLAIN_BYTES + nameLen, ERR.MALFORMED, 'file header name truncated');
  const name = pt.subarray(HEADER_PLAIN_BYTES, HEADER_PLAIN_BYTES + nameLen);
  assert(chunkSize > 0 && chunkSize <= 64 * 1024 * 1024, ERR.MALFORMED, 'bad chunk size');
  assert(totalSize <= Number.MAX_SAFE_INTEGER, ERR.MALFORMED, 'file too large');
  assert(realSize <= totalSize, ERR.MALFORMED, 'real size exceeds padded size');
  return { version, suite, chunkSize, totalSize, realSize, flags, name: Buffer.from(name) };
}

function readU64Safe(buf, off) {
  const v = buf.readBigUInt64BE(off);
  assert(v <= BigInt(Number.MAX_SAFE_INTEGER), ERR.MALFORMED, 'value out of range');
  return Number(v);
}

function chunkAad(index, final) {
  // Include the plaintext length class so a chunk cannot be shrunk into
  // another valid chunk.
  return concat(LABEL_CHUNK, u64be(index), final ? Buffer.from([1]) : Buffer.from([0]));
}

/**
 * Encrypt a whole buffer (streaming internally, constant memory at the file
 * level). Returns the container bytes.
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} masterKey 32 bytes
 */
export function encryptBuffer(plaintext, masterKey, opts = {}) {
  const chunkSize = opts.chunkSize ?? DEFAULT_CHUNK_SIZE;
  const data = toBytes(plaintext);
  const salt = opts.salt !== undefined ? toBytes(opts.salt) : randomBytes(16);
  assert(salt.length === 16, ERR.RANGE, 'container salt must be 16 bytes');
  const key = typeof masterKey === 'string' ? keyFromPassphrase(masterKey, salt, opts.scrypt) : masterKey;
  const sealKey = new SealKey(key);
  try {
    const total = opts.padTo !== undefined ? padme(data.length, opts.padTo) : data.length;
    assert(total >= data.length, ERR.RANGE, 'padTo smaller than plaintext');
    const header = sealKey.seal(
      buildHeader({
        chunkSize,
        totalSize: total,
        realSize: data.length,
        flags: opts.flags ?? 0,
        name: opts.name ?? EMPTY,
      }),
      LABEL_HEADER,
    );
    const parts = [salt, u32be(header.length), header];
    const padded = total === data.length ? data : concat(data, randomBytes(total - data.length));
    const chunks = Math.max(1, Math.ceil(total / chunkSize));
    for (let i = 0; i < chunks; i += 1) {
      const final = i === chunks - 1;
      const chunk = padded.subarray(i * chunkSize, Math.min(total, (i + 1) * chunkSize));
      const env = sealKey.seal(chunk, chunkAad(i, final));
      parts.push(u32be(env.length), env);
    }
    return Buffer.concat(parts);
  } finally {
    sealKey.destroy();
  }
}

/** Decrypt a container held in memory. */
export function decryptBuffer(container, masterKey, opts = {}) {
  const buf = toBytes(container);
  assert(buf.length >= 16 + 4 + 80, ERR.TRUNCATED, 'container too short');
  const salt = buf.subarray(0, 16);
  const key = typeof masterKey === 'string' ? keyFromPassphrase(masterKey, salt, opts.scrypt) : masterKey;
  const sealKey = new SealKey(key);
  try {
    let off = 16;
    const headerLen = readU32(buf, off);
    off += 4;
    assert(headerLen > 0 && off + headerLen <= buf.length, ERR.TRUNCATED, 'header envelope truncated');
    const header = parseHeader(sealKey.open(buf.subarray(off, off + headerLen), LABEL_HEADER));
    off += headerLen;

    const parts = [];
    let index = 0;
    let produced = 0;
    let sawFinal = false;
    while (off < buf.length) {
      assert(off + 4 <= buf.length, ERR.TRUNCATED, 'chunk length truncated');
      const len = readU32(buf, off);
      off += 4;
      assert(len >= 80 && off + len <= buf.length, ERR.TRUNCATED, 'chunk envelope truncated');
      const env = buf.subarray(off, off + len);
      off += len;

      // Try final first only when the declared total requires it; AAD binding
      // makes the wrong guess fail authentication.
      const remaining = header.totalSize - produced;
      const isLastByLength = remaining <= header.chunkSize;
      const plain = sealKey.open(env, chunkAad(index, isLastByLength));
      if (isLastByLength) sawFinal = true;
      produced += plain.length;
      assert(produced <= header.totalSize, ERR.MALFORMED, 'chunk exceeds declared size');
      parts.push(plain);
      index += 1;
      if (sawFinal) {
        assert(off === buf.length, ERR.MALFORMED, 'trailing bytes after final chunk');
        break;
      }
    }
    assert(sawFinal, ERR.TRUNCATED, 'container ended before final chunk');
    assert(produced === header.totalSize, ERR.MALFORMED, 'container size mismatch');
    const padded = Buffer.concat(parts);
    assert(header.realSize <= padded.length, ERR.MALFORMED, 'real size exceeds payload');
    return { plaintext: padded.subarray(0, header.realSize), header };
  } finally {
    sealKey.destroy();
  }
}

/**
 * Encrypt a file on disk with constant memory. Returns container metadata.
 * @param {string} sourcePath
 * @param {string} destPath
 * @param {Uint8Array|string} masterKey
 */
export function encryptFileSync(sourcePath, destPath, masterKey, opts = {}) {
  const chunkSize = opts.chunkSize ?? DEFAULT_CHUNK_SIZE;
  const inFd = openSync(sourcePath, 'r');
  try {
    const size = fstatSync(inFd).size;
    const total = opts.padTo !== undefined ? padme(size, opts.padTo) : size;
    assert(total >= size, ERR.RANGE, 'padTo smaller than file');
    const salt = randomBytes(16);
    const key = typeof masterKey === 'string' ? keyFromPassphrase(masterKey, salt, opts.scrypt) : masterKey;
    const sealKey = new SealKey(key);
    const outFd = openSync(destPath, 'w');
    try {
      const header = sealKey.seal(
        buildHeader({
          chunkSize,
          totalSize: total,
          realSize: size,
          flags: opts.flags ?? 0,
          name: opts.name ?? EMPTY,
        }),
        LABEL_HEADER,
      );
      writeSync(outFd, salt);
      writeSync(outFd, u32be(header.length));
      writeSync(outFd, header);
      let outBytes = 16 + 4 + header.length;

      const chunk = Buffer.allocUnsafe(chunkSize);
      const chunks = Math.max(1, Math.ceil(total / chunkSize));
      for (let i = 0; i < chunks; i += 1) {
        const want = Math.min(chunkSize, total - i * chunkSize);
        const real = Math.max(0, Math.min(want, size - i * chunkSize));
        let fill = 0;
        while (fill < real) {
          const n = readSync(inFd, chunk, fill, real - fill, i * chunkSize + fill);
          if (n <= 0) throw new PraetorError(ERR.TRUNCATED, 'unexpected end of source file');
          fill += n;
        }
        if (fill < want) {
          const pad = randomBytes(want - fill);
          pad.copy(chunk, fill);
        }
        const env = sealKey.seal(chunk.subarray(0, want), chunkAad(i, i === chunks - 1));
        writeSync(outFd, u32be(env.length));
        writeSync(outFd, env);
        outBytes += 4 + env.length;
      }
      fsyncSync(outFd);
      return { bytesIn: size, bytesOut: outBytes, chunks, total, salt };
    } finally {
      closeSync(outFd);
    }
  } finally {
    closeSync(inFd);
  }
}

/**
 * Decrypt a container on disk into `destPath`.
 *
 * Decryption is atomic: plaintext is written to a sibling temp file and only
 * renamed over the destination after the final chunk authenticates. A
 * truncated or forged container therefore cannot leave partial plaintext on
 * disk or clobber an existing file.
 */
export function decryptFileSync(sourcePath, destPath, masterKey, opts = {}) {
  const inFd = openSync(sourcePath, 'r');
  const tempPath = `${destPath}.praetor-tmp-${randomBytes(6).toString('hex')}`;
  let outFd = null;
  let sealKey = null;
  try {
    const size = fstatSync(inFd).size;
    assert(size >= 16 + 4 + 80, ERR.TRUNCATED, 'container too short');
    const salt = Buffer.allocUnsafe(16);
    readExact(inFd, salt, 16, 0);
    const key = typeof masterKey === 'string' ? keyFromPassphrase(masterKey, salt, opts.scrypt) : masterKey;
    sealKey = new SealKey(key);

    const lenBuf = Buffer.allocUnsafe(4);
    readExact(inFd, lenBuf, 4, 16);
    const headerLen = lenBuf.readUInt32BE(0);
    assert(headerLen >= 80 && 20 + headerLen <= size, ERR.TRUNCATED, 'header envelope truncated');
    const headerEnv = Buffer.allocUnsafe(headerLen);
    readExact(inFd, headerEnv, headerLen, 20);
    const header = parseHeader(sealKey.open(headerEnv, LABEL_HEADER));

    outFd = openSync(tempPath, 'wx', 0o600);
    let off = 20 + headerLen;
    let index = 0;
    let produced = 0;
    let written = 0;
    let wroteFinal = false;
    while (off < size) {
      assert(off + 4 <= size, ERR.TRUNCATED, 'chunk length truncated');
      readExact(inFd, lenBuf, 4, off);
      const len = lenBuf.readUInt32BE(0);
      off += 4;
      assert(len >= 80 && off + len <= size, ERR.TRUNCATED, 'chunk envelope truncated');
      const env = Buffer.allocUnsafe(len);
      readExact(inFd, env, len, off);
      off += len;

      const remaining = header.totalSize - produced;
      const isLastByLength = remaining <= header.chunkSize;
      const plain = sealKey.open(env, chunkAad(index, isLastByLength));
      produced += plain.length;
      assert(produced <= header.totalSize, ERR.MALFORMED, 'chunk exceeds declared size');
      const take = Math.min(plain.length, header.realSize - written);
      if (take > 0) {
        writeSync(outFd, plain.subarray(0, take));
        written += take;
      }
      index += 1;
      if (isLastByLength) {
        wroteFinal = true;
        assert(off === size, ERR.MALFORMED, 'trailing bytes after final chunk');
        break;
      }
    }
    assert(wroteFinal, ERR.TRUNCATED, 'container ended before final chunk');
    assert(produced === header.totalSize, ERR.MALFORMED, 'container size mismatch');
    assert(written === header.realSize, ERR.MALFORMED, 'real size mismatch');
    fsyncSync(outFd);
    closeSync(outFd);
    outFd = null;
    renameSync(tempPath, destPath);
    return { bytesIn: size, bytesOut: written, header };
  } catch (err) {
    if (outFd !== null) {
      try {
        closeSync(outFd);
      } catch {
        // The original error is more useful.
      }
      outFd = null;
    }
    try {
      unlinkSync(tempPath);
    } catch {
      // Temp file may never have been created.
    }
    throw err;
  } finally {
    if (outFd !== null) {
      try {
        closeSync(outFd);
      } catch {
        // Best effort.
      }
    }
    sealKey?.destroy();
    closeSync(inFd);
  }
}

function readExact(fd, buf, length, position) {
  let got = 0;
  while (got < length) {
    const n = readSync(fd, buf, got, length - got, position + got);
    if (n <= 0) throw new PraetorError(ERR.TRUNCATED, 'unexpected end of container');
    got += n;
  }
}

export { ctEqual, sha256, EMPTY };
