import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ERR,
  SecureChannel,
  SealKey,
  PraetorError,
  decryptBuffer,
  encryptBuffer,
  randomBytes,
  psealOpen,
} from '../src/index.js';

/** Deterministic PRNG so failures reproduce exactly. */
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng, max) {
  return Math.floor(rng() * max);
}

test('property: 400 envelopes roundtrip and resist a random bit flip', () => {
  const rng = mulberry32(0x5eed);
  for (let i = 0; i < 400; i += 1) {
    const key = randomBytes(32);
    const pt = randomBytes(randInt(rng, 4096));
    const aad = randomBytes(randInt(rng, 64));
    const env = psealOpen.length >= 0 ? null : null;
    void env;
    const k = new SealKey(key);
    const sealed = k.seal(pt, aad);
    assert.deepEqual(k.open(sealed, aad), pt);
    const bad = Buffer.from(sealed);
    bad[randInt(rng, bad.length)] ^= 1 << randInt(rng, 8);
    assert.throws(
      () => k.open(bad, aad),
      (e) => e instanceof PraetorError && e.code === ERR.AUTH,
    );
    k.destroy();
  }
});

test('property: 60 containers roundtrip across random chunk sizes', () => {
  const rng = mulberry32(0xc0ffee);
  for (let i = 0; i < 60; i += 1) {
    const key = randomBytes(32);
    const n = randInt(rng, 20000);
    const pt = randomBytes(n);
    const chunkSize = [256, 512, 1024, 4096][randInt(rng, 4)];
    const ct = encryptBuffer(pt, key, { chunkSize });
    const { plaintext, header } = decryptBuffer(ct, key);
    assert.deepEqual(plaintext, pt);
    assert.equal(header.totalSize, n);
  }
});

test('property: 40 channels fragment, shuffle and reassemble', () => {
  const rng = mulberry32(0xbadd);
  for (let i = 0; i < 40; i += 1) {
    const cellSize = [128, 256, 512][randInt(rng, 3)];
    const chain = randomBytes(32);
    const a = new SecureChannel({ sendChain: chain, recvChain: randomBytes(32), cellSize });
    const b = new SecureChannel({ sendChain: randomBytes(32), recvChain: chain, cellSize });
    const msg = randomBytes(randInt(rng, 5000));
    const cells = a.send(msg);
    for (let j = cells.length - 1; j > 0; j -= 1) {
      const k = randInt(rng, j + 1);
      [cells[j], cells[k]] = [cells[k], cells[j]];
    }
    let out = null;
    for (const c of cells) {
      const ev = b.receive(c);
      if (ev?.data) out = ev.data;
    }
    assert.deepEqual(out, msg);
  }
});

test('property: a flipped cell always fails, never returns data', () => {
  const rng = mulberry32(0xfeed);
  const chain = randomBytes(32);
  for (let i = 0; i < 100; i += 1) {
    const a = new SecureChannel({ sendChain: chain, recvChain: randomBytes(32), cellSize: 256 });
    const b = new SecureChannel({ sendChain: randomBytes(32), recvChain: chain, cellSize: 256 });
    const [cell] = a.send(randomBytes(randInt(rng, 200)));
    const bad = Buffer.from(cell);
    bad[randInt(rng, bad.length)] ^= 0xff;
    assert.throws(
      () => b.receive(bad),
      (e) => e instanceof PraetorError && e.code === ERR.AUTH,
    );
  }
});
