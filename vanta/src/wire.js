// VANTA/WIRE — fixed-cell obfuscated framing.
//
// Every record on the wire is the VSEAL envelope of a fixed-size cell, so the
// first bytes are indistinguishable from random and the record length never
// depends on the payload. There is no magic, no version byte and no length
// field in cleartext: a receiver with the wrong key cannot tell a VANTA
// stream from random data, and a correct receiver identifies records by
// successful authentication (trial decryption over a small epoch window).
//
// Cell plaintext (always exactly `cellSize` bytes):
//   type(1) flags(1) fragIndex(2) fragCount(2) msgId(8) payloadLen(2) payload.. pad..
//
// Wire cell: nonce(16) || prefix(16) || ct(cellSize) || tag(32) = cellSize + 64
import { Buffer } from 'node:buffer';
import { SealKey } from './aead.js';
import { RecvRatchet, SendRatchet, DEFAULT_RATCHET_INTERVAL } from './ratchet.js';
import {
  EMPTY,
  ERR,
  VantaError,
  assert,
  concat,
  randomBytes,
  readU16,
  readU64,
  toBytes,
  u16be,
  u64be,
} from './util.js';

export const CELL_DATA = 0;
export const CELL_PAD = 1;
export const CELL_CTRL = 2;
export const CELL_FIN = 3;

export const CELL_HEADER_BYTES = 16;
// 16 nonce + 16 SIV prefix + 16 Poly1305 tag + 32 commitment tag.
export const CELL_OVERHEAD = 80;
export const DEFAULT_CELL_SIZE = 1024;
export const MAX_CELL_SIZE = 65535 - CELL_HEADER_BYTES;

const LABEL_CELL = Buffer.from('VANTA/1/cell');

/** Build the fixed-size inner plaintext of a cell. */
export function packCell({
  type = CELL_DATA,
  flags = 0,
  msgId = 0n,
  fragIndex = 0,
  fragCount = 1,
  payload = EMPTY,
  cellSize = DEFAULT_CELL_SIZE,
}) {
  const body = toBytes(payload, 'payload');
  assert(cellSize >= CELL_HEADER_BYTES + 1 && cellSize <= MAX_CELL_SIZE, ERR.RANGE, 'bad cell size');
  assert(body.length <= cellSize - CELL_HEADER_BYTES, ERR.RANGE, 'payload exceeds cell capacity');
  assert(fragCount >= 1 && fragCount <= 0xffff, ERR.RANGE, 'bad fragment count');
  assert(fragIndex < fragCount, ERR.RANGE, 'bad fragment index');

  const head = Buffer.allocUnsafe(CELL_HEADER_BYTES);
  head.writeUInt8(type & 0xff, 0);
  head.writeUInt8(flags & 0xff, 1);
  head.writeUInt16BE(fragIndex, 2);
  head.writeUInt16BE(fragCount, 4);
  head.writeBigUInt64BE(BigInt(msgId), 6);
  head.writeUInt16BE(body.length, 14);

  const padLen = cellSize - CELL_HEADER_BYTES - body.length;
  const pad = padLen > 0 ? randomBytes(padLen) : EMPTY;
  return Buffer.concat([head, body, pad]);
}

export function unpackCell(plain, cellSize = DEFAULT_CELL_SIZE) {
  const pt = toBytes(plain);
  assert(pt.length === cellSize, ERR.MALFORMED, 'cell has wrong size');
  const type = pt.readUInt8(0);
  const flags = pt.readUInt8(1);
  const fragIndex = readU16(pt, 2);
  const fragCount = readU16(pt, 4);
  const msgId = readU64(pt, 6);
  const payloadLen = readU16(pt, 14);
  assert(type <= CELL_FIN, ERR.MALFORMED, 'unknown cell type');
  assert(fragCount >= 1, ERR.MALFORMED, 'bad fragment count');
  assert(fragIndex < fragCount, ERR.MALFORMED, 'bad fragment index');
  assert(
    payloadLen <= cellSize - CELL_HEADER_BYTES,
    ERR.MALFORMED,
    'payload length exceeds cell',
  );
  return {
    type,
    flags,
    fragIndex,
    fragCount,
    msgId,
    payload: pt.subarray(CELL_HEADER_BYTES, CELL_HEADER_BYTES + payloadLen),
  };
}

/** Keyed cell codec for one epoch key. */
export class CellCipher {
  constructor(recordKey, cellSize = DEFAULT_CELL_SIZE) {
    assert(cellSize >= CELL_HEADER_BYTES + 1 && cellSize <= MAX_CELL_SIZE, ERR.RANGE, 'bad cell size');
    this.cellSize = cellSize;
    this.sealKey = recordKey instanceof SealKey ? recordKey : new SealKey(recordKey);
    this.aad = concat(LABEL_CELL, u16be(cellSize));
  }

  sealCell(cell) {
    const plain = packCell({ ...cell, cellSize: this.cellSize });
    return this.sealKey.seal(plain, this.aad);
  }

  openCell(wire) {
    return unpackCell(this.sealKey.open(wire, this.aad), this.cellSize);
  }

  destroy() {
    this.sealKey.destroy();
  }
}

/** Bounded replay window over (msgId, fragment). */
export class ReplayWindow {
  constructor(capacity = 4096) {
    this.capacity = capacity;
    this.seen = new Map(); // msgId(string) -> Set(fragIndex)
    this.order = [];
  }

  /** Records the fragment, throwing on a replay. */
  accept(msgId, fragIndex) {
    const id = String(msgId);
    let set = this.seen.get(id);
    if (set === undefined) {
      set = new Set();
      this.seen.set(id, set);
      this.order.push(id);
    }
    if (set.has(fragIndex)) throw new VantaError(ERR.REPLAY, 'replayed cell');
    set.add(fragIndex);
    while (this.order.length > this.capacity) {
      const old = this.order.shift();
      this.seen.delete(old);
    }
  }
}

/** Reassembles fragmented messages. */
export class Assembler {
  constructor({ maxMessageBytes = 64 * 1024 * 1024, maxFragments = 1 << 16 } = {}) {
    this.pending = new Map();
    this.maxMessageBytes = maxMessageBytes;
    this.maxFragments = maxFragments;
  }

  push(cell) {
    const id = String(cell.msgId);
    let slot = this.pending.get(id);
    if (slot === undefined) {
      assert(cell.fragCount <= this.maxFragments, ERR.POLICY, 'too many fragments');
      slot = { count: cell.fragCount, parts: new Array(cell.fragCount), have: 0, bytes: 0 };
      this.pending.set(id, slot);
    }
    assert(slot.count === cell.fragCount, ERR.MALFORMED, 'inconsistent fragment count');
    if (slot.parts[cell.fragIndex] !== undefined) return null;
    slot.parts[cell.fragIndex] = Buffer.from(cell.payload);
    slot.have += 1;
    slot.bytes += cell.payload.length;
    assert(slot.bytes <= this.maxMessageBytes, ERR.POLICY, 'message exceeds size policy');
    if (slot.have !== slot.count) return null;
    this.pending.delete(id);
    return { msgId: cell.msgId, data: Buffer.concat(slot.parts) };
  }

  /** Fail closed if a partially received message is abandoned. */
  reset() {
    this.pending.clear();
  }
}

/**
 * A full duplex channel: handshake chains in, authenticated cells out.
 */
export class SecureChannel {
  constructor({
    sendChain,
    recvChain,
    cellSize = DEFAULT_CELL_SIZE,
    ratchetInterval = DEFAULT_RATCHET_INTERVAL,
    maxMessageBytes = 64 * 1024 * 1024,
    msgIdStart,
  }) {
    this.cellSize = cellSize;
    this.sendRatchet = new SendRatchet(sendChain, ratchetInterval);
    this.recvRatchet = new RecvRatchet(recvChain, ratchetInterval);
    this.replay = new ReplayWindow();
    this.assembler = new Assembler({ maxMessageBytes });
    this.nextMsgId = msgIdStart ?? (BigInt(`0x${randomBytes(6).toString('hex')}`) << 16n);
    this.sendSeal = null;
    this.sendSealEpoch = -1;
    this.payloadCapacity = cellSize - CELL_HEADER_BYTES;
  }

  #sealForSend() {
    if (this.sendSeal === null || this.sendSealEpoch !== this.sendRatchet.epoch) {
      this.sendSeal?.destroy();
      this.sendSeal = new CellCipher(this.sendRatchet.peek(), this.cellSize);
      this.sendSealEpoch = this.sendRatchet.epoch;
    }
    return this.sendSeal;
  }

  /** Fragment and seal one application message into wire cells. */
  send(data) {
    const body = toBytes(data, 'message');
    const max = this.payloadCapacity;
    const count = Math.max(1, Math.ceil(body.length / max));
    assert(count <= 0xffff, ERR.POLICY, 'message needs too many fragments');
    const msgId = this.nextMsgId;
    this.nextMsgId += 1n;
    const out = [];
    for (let i = 0; i < count; i += 1) {
      const payload = body.subarray(i * max, Math.min(body.length, (i + 1) * max));
      const cell = {
        type: i === count - 1 ? CELL_FIN : CELL_DATA,
        msgId,
        fragIndex: i,
        fragCount: count,
        payload,
      };
      const cipher = this.#sealForSend();
      out.push(cipher.sealCell(cell));
      this.sendRatchet.next();
    }
    return out;
  }

  /** One fixed-size padding cell (cover traffic). */
  sendPadding() {
    const cipher = this.#sealForSend();
    // Padding must carry a unique id, otherwise the peer's replay window
    // rejects the second cover cell as a duplicate.
    const cell = cipher.sealCell({ type: CELL_PAD, msgId: this.nextMsgId, payload: EMPTY });
    this.nextMsgId += 1n;
    this.sendRatchet.next();
    return cell;
  }

  /**
   * Authenticate and decode one wire cell.
   * @returns {{type: number, msgId: bigint, data?: Buffer} | null}
   */
  receive(wire) {
    let cell;
    let epoch;
    for (const candidate of this.recvRatchet.candidates()) {
      try {
        const cipher = new CellCipher(candidate.key, this.cellSize);
        cell = cipher.openCell(wire);
        cipher.destroy();
        epoch = candidate.epoch;
        break;
      } catch (err) {
        if (err instanceof VantaError && err.code === ERR.AUTH) continue;
        throw err;
      }
    }
    if (cell === undefined) throw new VantaError(ERR.AUTH, 'cell failed authentication');
    this.replay.accept(cell.msgId, cell.fragIndex);
    this.recvRatchet.commit(epoch);

    if (cell.type === CELL_PAD) return null;
    const done = this.assembler.push(cell);
    if (done === null) return { type: cell.type, msgId: cell.msgId };
    return { type: CELL_FIN, msgId: done.msgId, data: done.data };
  }

  destroy() {
    this.sendRatchet.destroy();
    this.recvRatchet.destroy();
    this.sendSeal?.destroy();
  }
}

/**
 * Deterministic cover-traffic schedule. Constant-rate cells are the only
 * defence that does not leak the *shape* of a conversation; random padding
 * alone is measurably insufficient against modern classifiers.
 * @returns {number[]} send times in milliseconds
 */
export function coverSchedule(count, intervalMs, jitter = 0.2, rng = randomBytes) {
  assert(count >= 0 && intervalMs > 0, ERR.RANGE, 'bad cover schedule parameters');
  const times = [];
  let t = 0;
  for (let i = 0; i < count; i += 1) {
    t += intervalMs;
    const j = jitter > 0 ? (rng(4).readUInt32BE(0) / 0xffffffff) * 2 * jitter - jitter : 0;
    times.push(Math.max(0, t + j * intervalMs));
  }
  return times;
}
