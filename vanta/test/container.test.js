import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  decryptBuffer,
  decryptFileSync,
  encryptBuffer,
  encryptFileSync,
  randomBytes,
  sha256,
} from '../src/index.js';

const key = Buffer.alloc(32, 11);

test('container roundtrips across boundaries', () => {
  for (const n of [0, 1, 15, 1023, 1024, 1025, 4096]) {
    const pt = randomBytes(n);
    const ct = encryptBuffer(pt, key, { chunkSize: 1024 });
    const out = decryptBuffer(ct, key);
    assert.deepEqual(out.plaintext, pt);
    assert.equal(out.header.totalSize, n);
  }
});

test('tampered file decryption leaves the destination untouched', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vanta-atomic-'));
  try {
    const source = join(dir, 'input.bin');
    const container = join(dir, 'input.vanta');
    const dest = join(dir, 'output.bin');
    const pt = randomBytes(2048);
    writeFileSync(source, pt);
    const ct = encryptBuffer(pt, key, { chunkSize: 512 });
    writeFileSync(container, ct.subarray(0, ct.length - 10));
    writeFileSync(dest, 'do not clobber me');
    assert.throws(() => decryptFileSync(container, dest, key));
    assert.equal(readFileSync(dest, 'utf8'), 'do not clobber me');
    assert.equal(
      readdirSync(dir).some((name) => name.includes('.vanta-tmp-')),
      false,
      'temporary plaintext must be removed',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('padmé padding hides exact length', () => {
  const pt = randomBytes(1000);
  const ct = encryptBuffer(pt, key, { padTo: 1 << 20 });
  const out = decryptBuffer(ct, key);
  assert.deepEqual(out.plaintext, pt);
  assert.ok(out.header.totalSize >= 1000);
  assert.ok(out.header.totalSize < 1000 * 1.12);
  assert.equal(out.header.realSize, 1000);
});

test('no plaintext marker survives on the wire', () => {
  const ct = encryptBuffer(Buffer.from('VANTA1 secret marker'), key);
  assert.equal(ct.includes(Buffer.from('VANTA')), false);
  assert.equal(ct.includes(Buffer.from('secret')), false);
});

test('chunk reordering and truncation are detected', () => {
  const pt = randomBytes(5000);
  const ct = encryptBuffer(pt, key, { chunkSize: 1024 });
  // Flip a length byte deep in the file.
  const bad = Buffer.from(ct);
  bad[bad.length - 5] ^= 0xff;
  assert.throws(() => decryptBuffer(bad, key));
  // Truncate the final chunk.
  assert.throws(() => decryptBuffer(ct.subarray(0, ct.length - 100), key));
});

test('wrong passphrase fails', () => {
  const ct = encryptBuffer(Buffer.from('hello'), 'correct horse battery staple', {
    scrypt: { N: 1 << 12 },
  });
  assert.throws(() => decryptBuffer(ct, 'wrong horse battery staple', { scrypt: { N: 1 << 12 } }));
  const out = decryptBuffer(ct, 'correct horse battery staple', { scrypt: { N: 1 << 12 } });
  assert.deepEqual(out.plaintext, Buffer.from('hello'));
});

test('file API roundtrips and matches buffer API', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vanta-'));
  try {
    const src = join(dir, 'in.bin');
    const mid = join(dir, 'out.vanta');
    const dst = join(dir, 'out.bin');
    const data = randomBytes(3 * 1024 * 1024 + 17);
    writeFileSync(src, data);
    encryptFileSync(src, mid, key, { chunkSize: 1 << 20 });
    assert.notDeepEqual(sha256(readFileSync(mid)), sha256(data));
    decryptFileSync(mid, dst, key);
    assert.deepEqual(readFileSync(dst), data);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
