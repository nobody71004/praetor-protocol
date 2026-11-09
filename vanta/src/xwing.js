// VANTA-KEM/1 — an X-Wing-structured hybrid KEM.
//
// X-Wing (draft-connolly-cfrg-xwing-kem, ePrint 2024/039) combines X25519 with
// ML-KEM-768 so that the shared secret stays secure if *either* component is
// secure. This keeps the X-Wing structure but applies a protocol-specific
// domain-separation label so VANTA shared secrets are never reused by another
// X-Wing deployment.
//
//   pk = ML-KEM-768.pk (1184) || X25519.pk (32)              = 1216 bytes
//   sk = ML-KEM-768.sk (2400) || X25519.sk (32)              = 2432 bytes
//   ct = ML-KEM-768.ct (1088) || X25519.ephemeral pk (32)    = 1120 bytes
//   ss = SHA3-256(label || ss_MLKEM || ss_X25519 || ct_X || pk_X)
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { Buffer } from 'node:buffer';
import { ERR, VantaError, assert, concat, ctEqual, sha3_256, toBytes } from './util.js';

export const XWING_LABEL = Buffer.from('VANTA-KEM/1 X-Wing');
export const XWING_PK_BYTES = 1184 + 32;
export const XWING_SK_BYTES = 2400 + 32;
export const XWING_CT_BYTES = 1088 + 32;
export const XWING_SS_BYTES = 32;
const ZERO32 = new Uint8Array(32);

function combiner(ssMl, ssX, ctX, pkX) {
  return sha3_256(XWING_LABEL, ssMl, ssX, ctX, pkX);
}

/** @returns {{publicKey: Buffer, secretKey: Buffer}} */
export function keygen() {
  const kem = ml_kem768.keygen();
  const skX = x25519.utils.randomSecretKey();
  const pkX = x25519.getPublicKey(skX);
  return {
    publicKey: concat(kem.publicKey, pkX),
    secretKey: concat(kem.secretKey, skX),
  };
}

/**
 * @param {Uint8Array} publicKey
 * @returns {{cipherText: Buffer, sharedSecret: Buffer}}
 */
export function encapsulate(publicKey) {
  const pk = toBytes(publicKey);
  assert(pk.length === XWING_PK_BYTES, ERR.KEY, 'invalid VANTA-KEM public key length');
  const pkM = pk.subarray(0, 1184);
  const pkX = pk.subarray(1184);
  // Reject low-order/identity X25519 inputs explicitly. Some backends throw
  // on an all-zero shared secret; do not rely on that behaviour.
  assert(!ctEqual(pkX, ZERO32), ERR.KEY, 'degenerate X25519 public key');
  try {
    const enc = ml_kem768.encapsulate(pkM);
    const esk = x25519.utils.randomSecretKey();
    const ctX = x25519.getPublicKey(esk);
    const ssX = x25519.getSharedSecret(esk, pkX);
    assert(!ctEqual(ssX, ZERO32), ERR.KEY, 'degenerate X25519 shared secret');
    return {
      cipherText: concat(enc.cipherText, ctX),
      sharedSecret: combiner(enc.sharedSecret, ssX, ctX, pkX),
    };
  } catch (cause) {
    if (cause instanceof VantaError) throw cause;
    throw new VantaError(ERR.KEY, 'VANTA-KEM encapsulation failed', cause);
  }
}

/**
 * @param {Uint8Array} cipherText
 * @param {Uint8Array} secretKey
 * @returns {Buffer}
 */
export function decapsulate(cipherText, secretKey) {
  const ct = toBytes(cipherText);
  const sk = toBytes(secretKey);
  assert(ct.length === XWING_CT_BYTES, ERR.MALFORMED, 'invalid VANTA-KEM ciphertext length');
  assert(sk.length === XWING_SK_BYTES, ERR.KEY, 'invalid VANTA-KEM secret key length');
  const ctX = ct.subarray(1088);
  const skM = sk.subarray(0, 2400);
  const skX = sk.subarray(2400);
  try {
    assert(!ctEqual(ctX, ZERO32), ERR.KEY, 'degenerate X25519 ciphertext key');
    const ssX = x25519.getSharedSecret(skX, ctX);
    assert(!ctEqual(ssX, ZERO32), ERR.AUTH, 'degenerate X25519 shared secret');
    const ssM = ml_kem768.decapsulate(ct.subarray(0, 1088), skM);
    // Re-derive pk_X from sk_X: decapsulation must not need extra key material.
    return combiner(ssM, ssX, ctX, x25519.getPublicKey(skX));
  } catch (cause) {
    throw new VantaError(ERR.AUTH, 'VANTA-KEM decapsulation failed', cause);
  }
}
