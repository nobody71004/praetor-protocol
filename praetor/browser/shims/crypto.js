// Browser replacements for the small Node `crypto` surface used by PRAETOR.
// All primitives come from @noble; randomness comes from WebCrypto.
import { Buffer } from 'buffer';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hmac } from '@noble/hashes/hmac';
import { hkdf } from '@noble/hashes/hkdf';
import { scrypt } from '@noble/hashes/scrypt';
import { sha256 } from '@noble/hashes/sha256';
import { sha3_256 } from '@noble/hashes/sha3';

function digestFactory(fn) {
  return () => {
    const parts = [];
    return {
      update(data) {
        parts.push(Buffer.from(data));
        return this;
      },
      digest() {
        return Buffer.from(fn(Buffer.concat(parts)));
      },
    };
  };
}

export function createHash(algorithm) {
  if (algorithm === 'sha256') return digestFactory(sha256)();
  if (algorithm === 'sha3-256') return digestFactory(sha3_256)();
  throw new Error(`browser shim does not support hash ${algorithm}`);
}

export function createHmac(algorithm, key) {
  if (algorithm !== 'sha256') throw new Error(`browser shim does not support HMAC ${algorithm}`);
  const parts = [];
  return {
    update(data) {
      parts.push(Buffer.from(data));
      return this;
    },
    digest() {
      return Buffer.from(hmac(sha256, Buffer.from(key), Buffer.concat(parts)));
    },
  };
}

export function hkdfSync(algorithm, ikm, salt, info, length) {
  if (algorithm !== 'sha256') throw new Error(`browser shim does not support HKDF ${algorithm}`);
  return Buffer.from(hkdf(sha256, ikm, salt, info, length));
}

export function randomBytes(size) {
  const webcrypto = globalThis.crypto;
  if (!webcrypto?.getRandomValues) throw new Error('WebCrypto getRandomValues is unavailable');
  const out = new Uint8Array(size);
  webcrypto.getRandomValues(out);
  return Buffer.from(out);
}

export function scryptSync(password, salt, dkLen, options = {}) {
  return Buffer.from(
    scrypt(password, salt, {
      N: options.N ?? 1 << 15,
      r: options.r ?? 8,
      p: options.p ?? 1,
      dkLen,
    }),
  );
}

export function timingSafeEqual(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i += 1) diff |= x[i] ^ y[i];
  return diff === 0;
}

function aead(key, nonce, aad) {
  if (Buffer.from(key).length !== 32) throw new Error('ChaCha20-Poly1305 requires a 32-byte key');
  if (Buffer.from(nonce).length !== 12) throw new Error('ChaCha20-Poly1305 requires a 12-byte nonce');
  return chacha20poly1305(Buffer.from(key), Buffer.from(nonce), Buffer.from(aad));
}

export function createCipheriv(algorithm, key, nonce) {
  if (algorithm !== 'chacha20-poly1305') throw new Error(`unsupported cipher ${algorithm}`);
  let ad = Buffer.alloc(0);
  const parts = [];
  let tag = null;
  return {
    setAAD(value) {
      ad = Buffer.from(value);
      return this;
    },
    update(data) {
      parts.push(Buffer.from(data));
      return Buffer.alloc(0);
    },
    final() {
      const sealed = Buffer.from(aead(key, nonce, ad).encrypt(Buffer.concat(parts)));
      tag = sealed.subarray(sealed.length - 16);
      return sealed.subarray(0, sealed.length - 16);
    },
    getAuthTag() {
      if (tag === null) throw new Error('getAuthTag before final');
      return tag;
    },
  };
}

export function createDecipheriv(algorithm, key, nonce) {
  if (algorithm !== 'chacha20-poly1305') throw new Error(`unsupported cipher ${algorithm}`);
  let ad = Buffer.alloc(0);
  let tag = null;
  const parts = [];
  return {
    setAuthTag(value) {
      tag = Buffer.from(value);
      return this;
    },
    setAAD(value) {
      ad = Buffer.from(value);
      return this;
    },
    update(data) {
      parts.push(Buffer.from(data));
      return Buffer.alloc(0);
    },
    final() {
      if (tag === null) throw new Error('setAuthTag is required');
      return Buffer.from(
        aead(key, nonce, ad).decrypt(Buffer.concat([Buffer.concat(parts), tag])),
      );
    },
  };
}
