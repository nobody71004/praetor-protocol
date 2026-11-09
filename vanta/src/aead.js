// VSEAL/1 — the VANTA sealed envelope.
//
// A synthetic-IV (SIV) authenticated-encryption construction composed from
// standard primitives:
//
//   k_siv, k_enc, k_com = HKDF-SHA256(master, "VANTA/1", "vseal", 96)
//   prefix  = HMAC-SHA256(k_siv, "VSEAL/1/siv" || nonce || aad || pt)[0..16]
//   ct      = ChaCha20-Poly1305(k_enc, prefix[0..12], pt, "VSEAL/1/aead" || aad)
//   tag     = HMAC-SHA256(k_com, "VSEAL/1/tag" || nonce || prefix || ct || H(aad))
//   wire    = nonce(16) || prefix(16) || ct || tag(32)          (probabilistic)
//   wire    =             prefix(16) || ct || tag(32)          (deterministic)
//
// Security argument (composition, not novelty):
//   * ChaCha20-Poly1305 gives IND-CPA + INT-CTXT (RFC 8439).
//   * Encrypt-then-MAC with independent keys adds an independent integrity
//     check (Bellare & Namprempre, EUROCRYPT 2000).
//   * Deriving the AEAD nonce from the plaintext via a PRF is the SIV
//     construction (Rogaway & Shrimpton, EUROCRYPT 2006; RFC 5297): reusing a
//     caller nonce reveals only whether two plaintexts are equal, never the
//     keystream. VSEAL therefore has no "nonce misuse" failure mode.
//   * tag covers the ciphertext under a third, independent key, and the
//     commitment of k_com is checked before decryption, making ciphertexts
//     key-committing (a ciphertext cannot verify under two different keys).
//   * prefix is recomputed from the decrypted plaintext, so a valid AEAD tag
//     alone cannot substitute a different (pt, nonce) pair.
//
// The one deliberate trade-off: deterministic mode leaks plaintext equality.
// Probabilistic mode (default) does not, because the random nonce is hashed
// into the SIV prefix.
import {
  Buffer,
} from 'node:buffer';
import {
  EMPTY,
  ERR,
  assert,
  chachaOpen,
  chachaSeal,
  concat,
  ctEqual,
  fail,
  hkdfSha256,
  hmacSha256,
  randomBytes,
  sha256,
  toBytes,
  u64be,
} from './util.js';

const LABEL_SALT = Buffer.from('VANTA/1');
const LABEL_INFO = Buffer.from('vseal');
const LABEL_SIV = Buffer.from('VSEAL/1/siv');
const LABEL_AEAD = Buffer.from('VSEAL/1/aead');
const LABEL_TAG = Buffer.from('VSEAL/1/tag');
const LABEL_AAD = Buffer.from('VSEAL/1/aad');

export const VSEAL_NONCE_BYTES = 16;
export const VSEAL_PREFIX_BYTES = 16;
export const VSEAL_TAG_BYTES = 32;
// The inner ChaCha20-Poly1305 ciphertext carries its own 16-byte tag.
export const VSEAL_AEAD_TAG_BYTES = 16;
export const VSEAL_OVERHEAD =
  VSEAL_NONCE_BYTES + VSEAL_PREFIX_BYTES + VSEAL_AEAD_TAG_BYTES + VSEAL_TAG_BYTES;
export const VSEAL_DETERMINISTIC_OVERHEAD =
  VSEAL_PREFIX_BYTES + VSEAL_AEAD_TAG_BYTES + VSEAL_TAG_BYTES;

/** Expanded key material for one master key. Zeroise with `destroy()`. */
export class SealKey {
  /** @param {Uint8Array} master 32 bytes */
  constructor(master) {
    const k = toBytes(master, 'master key');
    assert(k.length === 32, ERR.KEY, 'VSEAL master key must be 32 bytes');
    const prk = hkdfSha256(k, LABEL_SALT, LABEL_INFO, 96);
    this.kSiv = Buffer.from(prk.subarray(0, 32));
    this.kEnc = Buffer.from(prk.subarray(32, 64));
    this.kCom = Buffer.from(prk.subarray(64, 96));
    prk.fill(0);
  }

  /**
   * @param {Uint8Array|string} plaintext
   * @param {Uint8Array|string} [aad]
   * @param {{nonce?: Uint8Array, deterministic?: boolean}} [opts]
   * @returns {Buffer}
   */
  seal(plaintext, aad = EMPTY, opts = {}) {
    const pt = toBytes(plaintext, 'plaintext');
    const ad = toBytes(aad, 'aad');
    const deterministic = opts.deterministic === true;
    let nonce = EMPTY;
    if (!deterministic) {
      nonce = opts.nonce !== undefined ? toBytes(opts.nonce, 'nonce') : randomBytes(VSEAL_NONCE_BYTES);
      assert(nonce.length === VSEAL_NONCE_BYTES, ERR.RANGE, 'VSEAL nonce must be 16 bytes');
    }

    const prefix = hmacSha256(
      this.kSiv,
      LABEL_SIV,
      nonce,
      u64be(ad.length),
      ad,
      u64be(pt.length),
      pt,
    ).subarray(0, VSEAL_PREFIX_BYTES);

    const ct = chachaSeal(this.kEnc, prefix.subarray(0, 12), pt, concat(LABEL_AEAD, ad));
    const tag = hmacSha256(this.kCom, LABEL_TAG, nonce, prefix, ct, sha256(LABEL_AAD, ad));

    return Buffer.concat([nonce, Buffer.from(prefix), ct, tag]);
  }

  /**
   * @param {Uint8Array} envelope
   * @param {Uint8Array|string} [aad]
   * @param {{deterministic?: boolean}} [opts]
   * @returns {Buffer}
   */
  open(envelope, aad = EMPTY, opts = {}) {
    const env = toBytes(envelope, 'envelope');
    const ad = toBytes(aad, 'aad');
    const deterministic = opts.deterministic === true;
    const head = deterministic ? 0 : VSEAL_NONCE_BYTES;
    const min = head + VSEAL_PREFIX_BYTES + VSEAL_TAG_BYTES;
    assert(env.length >= min, ERR.TRUNCATED, 'VSEAL envelope truncated');

    const nonce = env.subarray(0, head);
    const prefix = env.subarray(head, head + VSEAL_PREFIX_BYTES);
    const ct = env.subarray(head + VSEAL_PREFIX_BYTES, env.length - VSEAL_TAG_BYTES);
    const tag = env.subarray(env.length - VSEAL_TAG_BYTES);

    const expected = hmacSha256(this.kCom, LABEL_TAG, nonce, prefix, ct, sha256(LABEL_AAD, ad));
    if (!ctEqual(tag, expected)) fail(ERR.AUTH, 'VSEAL authentication failed');

    const pt = chachaOpen(this.kEnc, prefix.subarray(0, 12), ct, concat(LABEL_AEAD, ad));

    // Bind the plaintext back to the prefix: a swapped-but-valid AEAD body
    // must not be accepted as a different message.
    const reproved = hmacSha256(
      this.kSiv,
      LABEL_SIV,
      nonce,
      u64be(ad.length),
      ad,
      u64be(pt.length),
      pt,
    ).subarray(0, VSEAL_PREFIX_BYTES);
    if (!ctEqual(prefix, reproved)) fail(ERR.AUTH, 'VSEAL prefix mismatch');

    return pt;
  }

  destroy() {
    for (const k of [this.kSiv, this.kEnc, this.kCom]) k.fill(0);
  }
}

/** Convenience wrapper; use `SealKey` directly on hot paths. */
export function seal(master, plaintext, aad, opts) {
  const key = master instanceof SealKey ? master : new SealKey(master);
  try {
    return key.seal(plaintext, aad, opts);
  } finally {
    if (!(master instanceof SealKey)) key.destroy();
  }
}

export function open(master, envelope, aad, opts) {
  const key = master instanceof SealKey ? master : new SealKey(master);
  try {
    return key.open(envelope, aad, opts);
  } finally {
    if (!(master instanceof SealKey)) key.destroy();
  }
}
