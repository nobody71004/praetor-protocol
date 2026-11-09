import test from 'node:test';
import assert from 'node:assert/strict';
import { padme, padmeLeakageBits } from '../src/index.js';

test('paper example: 9 bytes pads to 10', () => {
  assert.equal(padme(9, 1 << 20), 10);
  assert.equal(padme(8, 1 << 20), 8);
  assert.equal(padme(10, 1 << 20), 10);
});

test('monotonic, idempotent, bounded overhead', () => {
  let prev = -1;
  for (let L = 1; L <= 200000; L = Math.ceil(L * 1.07) + 1) {
    const p = padme(L, 1 << 21);
    assert.ok(p >= L);
    assert.equal(padme(p, 1 << 21), p);
    assert.ok(p <= Math.ceil(L * 1.12) + 2, `overhead too high at ${L}: ${p}`);
    assert.ok(p >= prev);
    prev = p;
  }
});

test('edge cases', () => {
  assert.equal(padme(0, 100), 0);
  assert.equal(padme(1, 100), 1);
  assert.ok(padme(100, 1 << 10) >= 100);
  assert.throws(() => padme(200, 100), /maxLength/);
});

test('leakage is far below raw length', () => {
  const small = padmeLeakageBits(1 << 10);
  const large = padmeLeakageBits(1 << 20);
  assert.ok(small < 10, `small leakage ${small}`);
  assert.ok(large < 20, `large leakage ${large}`);
  assert.ok(large >= small);
  assert.ok(large < 20 && 20 === Math.log2(1 << 20));
});
