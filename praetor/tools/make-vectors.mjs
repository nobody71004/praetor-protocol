// Generates vectors/praetor-vectors.json, shared by the JS and Rust
// implementations. Deterministic except for the KEM encapsulation, whose
// ciphertext is pinned so Rust can verify decapsulation interop.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SealKey,
  XWING_CT_BYTES,
  XWING_PK_BYTES,
  XWING_SK_BYTES,
  hex,
  kemDecapsulate as decapsulate,
  kemEncapsulate as encapsulate,
  kemKeygen,
  padme,
  randomBytes,
  shamirCombine,
  shamirSplit,
} from '../src/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const key = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
const aad = Buffer.from('PRAETOR test vector');
const nonce = Buffer.from('f0e0d0c0b0a090807060504030201000', 'hex');
const plaintexts = ['', 'a', 'the quick brown fox jumps over the lazy dog', 'x'.repeat(1000)].map(
  (s) => Buffer.from(s),
);

const k = new SealKey(key);
const aead = plaintexts.map((pt) => ({
  plaintextHex: hex(pt),
  aadHex: hex(aad),
  nonceHex: hex(nonce),
  probabilisticHex: hex(k.seal(pt, aad, { nonce })),
  deterministicHex: hex(k.seal(pt, aad, { deterministic: true })),
}));

const padmeCases = [];
for (const L of [0, 1, 2, 8, 9, 10, 15, 16, 100, 1000, 4095, 4096, 100000]) {
  padmeCases.push({ length: L, max: 1 << 20, padded: padme(L, 1 << 20) });
}

const kp = kemKeygen();
const enc = encapsulate(kp.publicKey);
if (enc.cipherText.length !== XWING_CT_BYTES) throw new Error('bad ct size');
if (kp.publicKey.length !== XWING_PK_BYTES || kp.secretKey.length !== XWING_SK_BYTES) {
  throw new Error('bad key size');
}
const dec = decapsulate(enc.cipherText, kp.secretKey);

const secret = randomBytes(32);
const shares = shamirSplit(secret, 5, 3, (n) => Buffer.alloc(n, 0x42));

const vectors = {
  version: 1,
  protocol: 'PRAETOR/1',
  generatedBy: 'praetor/tools/make-vectors.mjs',
  aead: { keyHex: hex(key), cases: aead },
  padme: padmeCases,
  kem: {
    publicKeyHex: hex(kp.publicKey),
    secretKeyHex: hex(kp.secretKey),
    cipherTextHex: hex(enc.cipherText),
    sharedSecretHex: hex(enc.sharedSecret),
    decapsulatedHex: hex(dec),
  },
  shamir: {
    threshold: 3,
    secretHex: hex(secret),
    sharesHex: shares.map(hex),
  },
};

const dir = join(root, 'vectors');
mkdirSync(dir, { recursive: true });
const path = join(dir, 'praetor-vectors.json');
writeFileSync(path, `${JSON.stringify(vectors, null, 2)}\n`);
process.stdout.write(`wrote ${path}\n`);
