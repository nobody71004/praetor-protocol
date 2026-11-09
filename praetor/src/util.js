// PRAETOR/1 — shared byte/primitive utilities (Node native backend).
//
// Every cryptographic primitive used here is a well-vetted, standard
// construction. PRAETOR contributes composition, framing and key lifecycle,
// never a home-grown block cipher or permutation.
import {
  createHash,
  createHmac,
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes as nodeRandomBytes,
  timingSafeEqual,
  scryptSync,
} from 'node:crypto';

export class PraetorError extends Error {
  /**
   * @param {string} code machine-readable failure code
   * @param {string} message human-readable message
   * @param {unknown} [cause]
   */
  constructor(code, message, cause) {
    super(message);
    this.name = 'PraetorError';
    this.code = code;
    if (cause !== undefined) this.cause = cause;
  }
}

export const ERR = Object.freeze({
  AUTH: 'AUTH_FAILED',
  MALFORMED: 'MALFORMED',
  TRUNCATED: 'TRUNCATED',
  REPLAY: 'REPLAY',
  VERSION: 'VERSION',
  KEY: 'KEY',
  POLICY: 'POLICY',
  RANGE: 'RANGE',
});

export function fail(code, message, cause) {
  throw new PraetorError(code, message, cause);
}

export function assert(cond, code, message) {
  if (!cond) throw new PraetorError(code, message);
}

/** Normalise any byte-like value to a Buffer without copying more than needed. */
export function toBytes(value, what = 'value') {
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  fail(ERR.MALFORMED, `${what} must be bytes or a string`);
}

export const EMPTY = Buffer.alloc(0);

export function concat(...parts) {
  const out = [];
  for (const p of parts) out.push(toBytes(p));
  return Buffer.concat(out);
}

export function u8(n) {
  const b = Buffer.allocUnsafe(1);
  b.writeUInt8(n & 0xff, 0);
  return b;
}

export function u16be(n) {
  const b = Buffer.allocUnsafe(2);
  b.writeUInt16BE(n, 0);
  return b;
}

export function u32be(n) {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

export function u64be(n) {
  const b = Buffer.allocUnsafe(8);
  b.writeBigUInt64BE(BigInt(n), 0);
  return b;
}

export function readU16(buf, off = 0) {
  return buf.readUInt16BE(off);
}

export function readU32(buf, off = 0) {
  return buf.readUInt32BE(off);
}

export function readU64(buf, off = 0) {
  return buf.readBigUInt64BE(off);
}

export function ctEqual(a, b) {
  const x = toBytes(a);
  const y = toBytes(b);
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}

export function randomBytes(n) {
  return nodeRandomBytes(n);
}

export function sha256(...parts) {
  const h = createHash('sha256');
  for (const p of parts) h.update(toBytes(p));
  return h.digest();
}

export function sha3_256(...parts) {
  const h = createHash('sha3-256');
  for (const p of parts) h.update(toBytes(p));
  return h.digest();
}

export function hmacSha256(key, ...parts) {
  const h = createHmac('sha256', toBytes(key, 'hmac key'));
  for (const p of parts) h.update(toBytes(p));
  return h.digest();
}

export function hkdfSha256(ikm, salt, info, length) {
  return Buffer.from(hkdfSync('sha256', toBytes(ikm), toBytes(salt), toBytes(info), length));
}

/** ChaCha20-Poly1305 (IETF, 96-bit nonce, 128-bit tag). Returns ct || tag. */
export function chachaSeal(key, nonce, plaintext, aad = EMPTY) {
  const pt = toBytes(plaintext);
  const cipher = createCipheriv('chacha20-poly1305', toBytes(key), toBytes(nonce), {
    authTagLength: 16,
  });
  const ad = toBytes(aad);
  if (ad.length > 0) cipher.setAAD(ad, { plaintextLength: pt.length });
  const body = Buffer.concat([cipher.update(pt), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}

export function chachaOpen(key, nonce, sealed, aad = EMPTY) {
  const input = toBytes(sealed);
  if (input.length < 16) fail(ERR.TRUNCATED, 'AEAD ciphertext shorter than tag');
  const body = input.subarray(0, input.length - 16);
  const tag = input.subarray(input.length - 16);
  const decipher = createDecipheriv('chacha20-poly1305', toBytes(key), toBytes(nonce), {
    authTagLength: 16,
  });
  decipher.setAuthTag(tag);
  const ad = toBytes(aad);
  if (ad.length > 0) decipher.setAAD(ad, { plaintextLength: body.length });
  try {
    return Buffer.concat([decipher.update(body), decipher.final()]);
  } catch (cause) {
    // Never distinguish padding failure from tag failure to the caller.
    throw new PraetorError(ERR.AUTH, 'authentication failed', cause);
  }
}

/** scrypt KDF used only for passphrase-protected containers. */
export function scryptKey(passphrase, salt, { N = 1 << 15, r = 8, p = 1, dkLen = 32 } = {}) {
  return scryptSync(toBytes(passphrase, 'passphrase'), toBytes(salt), dkLen, {
    N,
    r,
    p,
    maxmem: 256 * 1024 * 1024,
  });
}

/** Best-effort zeroisation of a secret buffer. */
export function wipe(buf) {
  if (buf instanceof Uint8Array) buf.fill(0);
  return buf;
}

export function hex(buf) {
  return Buffer.from(toBytes(buf)).toString('hex');
}

export function fromHex(s, what = 'hex') {
  if (typeof s !== 'string' || s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) {
    fail(ERR.MALFORMED, `${what} is not valid hex`);
  }
  return Buffer.from(s, 'hex');
}

export function toBase64(buf) {
  return Buffer.from(toBytes(buf)).toString('base64');
}

export function fromBase64(s, what = 'base64') {
  if (typeof s !== 'string') fail(ERR.MALFORMED, `${what} is not a string`);
  return Buffer.from(s, 'base64');
}
