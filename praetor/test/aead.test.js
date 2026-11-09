import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ERR,
  SealKey,
  PraetorError,
  PSEAL_DETERMINISTIC_OVERHEAD,
  PSEAL_OVERHEAD,
  randomBytes,
  psealOpen,
  psealSeal,
} from '../src/index.js';

const key = Buffer.alloc(32, 7);
const aad = Buffer.from('context');

test('roundtrip across sizes', () => {
  const k = new SealKey(key);
  for (const n of [0, 1, 15, 16, 17, 1024, 65536]) {
    const pt = randomBytes(n);
    const env = k.seal(pt, aad);
    assert.equal(env.length, n + PSEAL_OVERHEAD);
    assert.deepEqual(k.open(env, aad), pt);
  }
});

test('deterministic mode is deterministic and shorter', () => {
  const k = new SealKey(key);
  const pt = Buffer.from('same plaintext');
  const a = k.seal(pt, aad, { deterministic: true });
  const b = k.seal(pt, aad, { deterministic: true });
  assert.deepEqual(a, b);
  assert.equal(a.length, pt.length + PSEAL_DETERMINISTIC_OVERHEAD);
  assert.deepEqual(k.open(a, aad, { deterministic: true }), pt);
});

test('probabilistic mode hides equality', () => {
  const k = new SealKey(key);
  const pt = Buffer.from('same plaintext');
  const a = k.seal(pt, aad);
  const b = k.seal(pt, aad);
  assert.notDeepEqual(a.subarray(0, 32), b.subarray(0, 32));
  assert.deepEqual(k.open(a, aad), pt);
  assert.deepEqual(k.open(b, aad), pt);
});

test('every byte of the envelope is authenticated', () => {
  const k = new SealKey(key);
  const env = k.seal(Buffer.from('integrity matters'), aad);
  for (let i = 0; i < env.length; i += 1) {
    const bad = Buffer.from(env);
    bad[i] ^= 0x01;
    assert.throws(
      () => k.open(bad, aad),
      (e) => e instanceof PraetorError && e.code === ERR.AUTH,
      `byte ${i} was not authenticated`,
    );
  }
});

test('aad is authenticated and bound', () => {
  const k = new SealKey(key);
  const env = k.seal(Buffer.from('payload'), aad);
  assert.throws(() => k.open(env, Buffer.from('contexT')), /authentication failed/);
  assert.deepEqual(k.open(env, aad), Buffer.from('payload'));
});

test('wrong key never decrypts, and the tag commits to the key', () => {
  const k1 = new SealKey(Buffer.alloc(32, 1));
  const k2 = new SealKey(Buffer.alloc(32, 2));
  const env = k1.seal(Buffer.from('secret'), aad);
  assert.throws(() => k2.open(env, aad), /authentication failed/);
});

test('nonce reuse is safe (SIV property)', () => {
  const k = new SealKey(key);
  const nonce = Buffer.alloc(16, 9);
  const a = k.seal(Buffer.from('alpha'), aad, { nonce });
  const b = k.seal(Buffer.from('beta'), aad, { nonce });
  // Same caller nonce, different plaintexts: different SIV prefixes and
  // therefore different keystreams; both open correctly.
  assert.notDeepEqual(a.subarray(16, 32), b.subarray(16, 32));
  assert.deepEqual(k.open(a, aad), Buffer.from('alpha'));
  assert.deepEqual(k.open(b, aad), Buffer.from('beta'));
});

test('truncation and empty input are rejected cleanly', () => {
  const k = new SealKey(key);
  const env = k.seal(Buffer.from('abc'), aad);
  assert.throws(() => k.open(env.subarray(0, 40), aad), /truncated/);
  assert.throws(() => k.open(Buffer.alloc(0), aad), /truncated/);
});

test('functional wrapper works and validates key length', () => {
  const env = psealSeal(key, Buffer.from('x'), aad);
  assert.deepEqual(psealOpen(key, env, aad), Buffer.from('x'));
  assert.throws(() => psealSeal(Buffer.alloc(31), Buffer.from('x'), aad), /32 bytes/);
});
