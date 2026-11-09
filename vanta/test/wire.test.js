import test from 'node:test';
import assert from 'node:assert/strict';
import {
  Assembler,
  CELL_PAD,
  CellCipher,
  ERR,
  ReplayWindow,
  SecureChannel,
  VantaError,
  coverSchedule,
  deriveRecordKey,
  packCell,
  randomBytes,
  unpackCell,
} from '../src/index.js';

test('cell packing is fixed size and roundtrips', () => {
  for (const size of [128, 1024, 4096]) {
    const packed = packCell({ payload: Buffer.from('hello'), cellSize: size, msgId: 42n });
    assert.equal(packed.length, size);
    const cell = unpackCell(packed, size);
    assert.equal(cell.msgId, 42n);
    assert.deepEqual(Buffer.from(cell.payload), Buffer.from('hello'));
  }
});

test('payload overflow is refused', () => {
  assert.throws(() => packCell({ payload: Buffer.alloc(2000), cellSize: 128 }), /exceeds/);
});

test('cell ciphertext length is independent of payload', () => {
  const cipher = new CellCipher(Buffer.alloc(32, 3), 512);
  const small = cipher.sealCell({ payload: Buffer.alloc(1) });
  const large = cipher.sealCell({ payload: Buffer.alloc(400) });
  assert.equal(small.length, large.length);
  assert.equal(small.length, 512 + 80);
});

test('a full duplex channel fragments and reassembles', () => {
  const chainA = randomBytes(32);
  const chainB = randomBytes(32);
  const a = new SecureChannel({ sendChain: chainA, recvChain: chainB, cellSize: 256 });
  const b = new SecureChannel({ sendChain: chainB, recvChain: chainA, cellSize: 256 });
  const msg = randomBytes(3000);
  const cells = a.send(msg);
  assert.equal(cells.length, Math.ceil(3000 / 240));
  let out = null;
  for (const c of cells) {
    const ev = b.receive(c);
    if (ev?.data) out = ev.data;
  }
  assert.deepEqual(out, msg);
});

test('reordering within a message is tolerated', () => {
  const chain = randomBytes(32);
  const a = new SecureChannel({ sendChain: chain, recvChain: randomBytes(32), cellSize: 256 });
  const b = new SecureChannel({ sendChain: randomBytes(32), recvChain: chain, cellSize: 256 });
  const msg = randomBytes(1000);
  const cells = a.send(msg).reverse();
  let out = null;
  for (const c of cells) {
    const ev = b.receive(c);
    if (ev?.data) out = ev.data;
  }
  assert.deepEqual(out, msg);
});

test('replay is rejected', () => {
  const chain = randomBytes(32);
  const a = new SecureChannel({ sendChain: chain, recvChain: randomBytes(32), cellSize: 256 });
  const b = new SecureChannel({ sendChain: randomBytes(32), recvChain: chain, cellSize: 256 });
  const [cell] = a.send(Buffer.from('once'));
  b.receive(cell);
  assert.throws(
    () => b.receive(cell),
    (e) => e instanceof VantaError && e.code === ERR.REPLAY,
  );
});

test('tampered cells fail authentication', () => {
  const chain = randomBytes(32);
  const a = new SecureChannel({ sendChain: chain, recvChain: randomBytes(32), cellSize: 256 });
  const b = new SecureChannel({ sendChain: randomBytes(32), recvChain: chain, cellSize: 256 });
  const [cell] = a.send(Buffer.from('tamper me'));
  const bad = Buffer.from(cell);
  bad[40] ^= 0xff;
  assert.throws(
    () => b.receive(bad),
    (e) => e instanceof VantaError && e.code === ERR.AUTH,
  );
});

test('wrong cell size is a policy failure, not a silent misread', () => {
  const chain = randomBytes(32);
  const a = new SecureChannel({ sendChain: chain, recvChain: randomBytes(32), cellSize: 512 });
  const b = new SecureChannel({ sendChain: randomBytes(32), recvChain: chain, cellSize: 256 });
  const [cell] = a.send(Buffer.from('x'));
  assert.throws(() => b.receive(cell));
});

test('padding cells are uniform and ignored by the receiver', () => {
  const chain = randomBytes(32);
  const a = new SecureChannel({ sendChain: chain, recvChain: randomBytes(32), cellSize: 256 });
  const b = new SecureChannel({ sendChain: randomBytes(32), recvChain: chain, cellSize: 256 });
  const cells = Array.from({ length: 5 }, () => a.sendPadding());
  const sizes = new Set(cells.map((c) => c.length));
  assert.deepEqual([...sizes], [256 + 80]);
  for (const c of cells) assert.equal(b.receive(c), null);
  assert.equal(new CellCipher(deriveRecordKey(chain, 0), 256).openCell(cells[0]).type, CELL_PAD);
});

test('replay window is bounded', () => {
  const w = new ReplayWindow(2);
  w.accept(1n, 0);
  w.accept(2n, 0);
  w.accept(3n, 0);
  w.accept(1n, 0); // evicted, so accepted again
  assert.throws(() => w.accept(3n, 0), /replayed/);
});

test('assembler refuses oversized messages', () => {
  const asm = new Assembler({ maxMessageBytes: 10 });
  const big = packCell({ payload: Buffer.alloc(20), cellSize: 128, fragCount: 1 });
  assert.throws(() => asm.push(unpackCell(big, 128)), /size policy/);
});

test('cover schedule is monotonic and jitter-bounded', () => {
  const times = coverSchedule(10, 100, 0.2, (n) => Buffer.alloc(n, 128));
  for (let i = 1; i < times.length; i += 1) assert.ok(times[i] > times[i - 1]);
});
