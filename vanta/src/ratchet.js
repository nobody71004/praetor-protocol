// Per-epoch record keys.
//
// Each direction of a session starts with a 32-byte chain key. Record `i`
// uses epoch e = floor(i / interval), with
//
//   chain[0]   = chain key from the handshake
//   chain[e+1] = HMAC-SHA256(chain[e], "VANTA/1/ratchet" || u32be(e))
//   key(e)     = HKDF-SHA256(chain[e], "VANTA/1/record", "VANTA/1/epoch" || u32be(e), 32)
//
// Old epoch keys are erased when they leave the receiver's window, which gives
// forward secrecy for *symmetric* keys inside a session: recovering the
// current key does not recover earlier record keys.
import { ERR, assert, concat, hkdfSha256, hmacSha256, toBytes, u32be } from './util.js';

const LABEL_RATCHET = Buffer.from('VANTA/1/ratchet');
const LABEL_RECORD_SALT = Buffer.from('VANTA/1/record');
const LABEL_RECORD_INFO = Buffer.from('VANTA/1/epoch');

export const DEFAULT_RATCHET_INTERVAL = 1024;

export function deriveRecordKey(chain, epoch) {
  return hkdfSha256(chain, LABEL_RECORD_SALT, concat(LABEL_RECORD_INFO, u32be(epoch)), 32);
}

export function stepChain(chain, epoch) {
  return hmacSha256(chain, LABEL_RATCHET, u32be(epoch));
}

/** Sender-side epoch tracking. */
export class SendRatchet {
  constructor(chain, interval = DEFAULT_RATCHET_INTERVAL) {
    this.chain = Buffer.from(toBytes(chain));
    assert(this.chain.length === 32, ERR.KEY, 'ratchet chain must be 32 bytes');
    assert(Number.isSafeInteger(interval) && interval >= 1, ERR.RANGE, 'bad ratchet interval');
    this.interval = interval;
    this.index = 0;
    this.epoch = 0;
    this.key = deriveRecordKey(this.chain, 0);
  }

  /** Key for the next record (does not advance). */
  peek() {
    return this.key;
  }

  /** Consume the key, advancing the ratchet at epoch boundaries. */
  next() {
    const out = this.key;
    this.index += 1;
    const nextEpoch = Math.floor(this.index / this.interval);
    if (nextEpoch !== this.epoch) {
      this.chain = stepChain(this.chain, this.epoch);
      this.epoch = nextEpoch;
      this.key = deriveRecordKey(this.chain, this.epoch);
    }
    return out;
  }

  destroy() {
    this.chain.fill(0);
    this.key.fill(0);
  }
}

/** Receiver-side epoch tracking with a bounded trial window. */
export class RecvRatchet {
  constructor(chain, interval = DEFAULT_RATCHET_INTERVAL, lookahead = 2) {
    this.chain0 = Buffer.from(toBytes(chain));
    assert(this.chain0.length === 32, ERR.KEY, 'ratchet chain must be 32 bytes');
    this.interval = interval;
    this.lookahead = lookahead;
    this.index = 0;
    this.chains = new Map([[0, Buffer.from(this.chain0)]]);
    this.keys = new Map();
  }

  chainAt(epoch) {
    if (this.chains.has(epoch)) return this.chains.get(epoch);
    let chain = this.chainAt(epoch - 1);
    chain = stepChain(chain, epoch - 1);
    this.chains.set(epoch, chain);
    return chain;
  }

  keyAt(epoch) {
    if (!this.keys.has(epoch)) this.keys.set(epoch, deriveRecordKey(this.chainAt(epoch), epoch));
    return this.keys.get(epoch);
  }

  /** Epochs worth trying for the next record, most likely first. */
  candidates() {
    const expected = Math.floor(this.index / this.interval);
    const out = [];
    for (let e = Math.max(0, expected - 1); e <= expected + this.lookahead; e += 1) {
      out.push({ epoch: e, key: this.keyAt(e) });
    }
    // Prefer the expected epoch.
    out.sort((a, b) => Math.abs(a.epoch - expected) - Math.abs(b.epoch - expected));
    return out;
  }

  /** Record that a record was accepted at `epoch`. */
  commit(epoch) {
    assert(epoch >= 0, ERR.RANGE, 'negative epoch');
    this.index += 1;
    // Drop key material that can no longer be needed.
    const expected = Math.floor(this.index / this.interval);
    const floor = Math.max(0, expected - this.lookahead - 1);
    for (const e of this.keys.keys()) {
      if (e < floor) {
        this.keys.get(e).fill(0);
        this.keys.delete(e);
      }
    }
    for (const e of this.chains.keys()) {
      if (e < floor) {
        this.chains.get(e).fill(0);
        this.chains.delete(e);
      }
    }
  }

  destroy() {
    this.chain0.fill(0);
    for (const k of this.keys.values()) k.fill(0);
    for (const c of this.chains.values()) c.fill(0);
    this.keys.clear();
    this.chains.clear();
  }
}
