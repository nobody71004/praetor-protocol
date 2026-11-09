// VANTA/GUARD — the defence layer for untrusted callers (including AI agents).
//
// A raw key is a bearer capability: anything that holds it can decrypt
// everything it ever protected. VANTA therefore separates *key material* from
// *authority to use it*. Callers (humans, services, LLM agents) receive an
// opaque capability id and are subject to a policy the keyring enforces:
//
//   * purpose binding — ciphertext AAD is bound to an intent string, so a
//     capability minted for "read:config" cannot decrypt "read:customers";
//   * quotas — ops/minute, bytes/op, total bytes, key age (cryptoperiod);
//   * oracle-probing lockout — repeated authentication failures trip the key;
//   * circuit breaker — coordinated failure floods stop all work early;
//   * canary keys — decoy capabilities that always "succeed" with fake data
//     and raise a high-severity alert, so exfiltration attempts are detected
//     instead of silently blocked;
//   * tamper-evident audit chain — every operation is hash-chained, so a rogue
//     agent cannot quietly rewrite history;
//   * split custody — Shamir 3-of-5 (or any k-of-n) key shares, so no single
//     agent or operator can reconstruct a high-value key;
//   * proof-of-work admission — makes mass handshake floods expensive for the
//     attacker while staying cheap for a legitimate client.
//
// This is an enforcement layer, not a cryptographic boundary: a caller that
// can read the raw key file bypasses it. Keep key material in a separate
// process/HSM and hand out capability ids only.
import { Buffer } from 'node:buffer';
import { SealKey } from './aead.js';
import {
  EMPTY,
  ERR,
  VantaError,
  assert,
  concat,
  hkdfSha256,
  hmacSha256,
  randomBytes,
  sha256,
  toBytes,
  u16be,
  u32be,
  u64be,
} from './util.js';

const LABEL_INTENT = Buffer.from('VANTA/1/intent');

function nowMs() {
  return Date.now();
}

/** AAD binding a ciphertext to one purpose. */
export function intentAad(purpose, aad = EMPTY) {
  const p = Buffer.from(toBytes(purpose, 'purpose'), 'utf8');
  assert(p.length > 0 && p.length <= 0xffff, ERR.POLICY, 'purpose must be 1..65535 bytes');
  return concat(LABEL_INTENT, u16be(p.length), p, toBytes(aad));
}

/** Token bucket with an injectable clock (milliseconds). */
export class TokenBucket {
  constructor({ capacity, refillPerSec, now = nowMs }) {
    assert(capacity > 0 && refillPerSec >= 0, ERR.RANGE, 'bad token bucket parameters');
    this.capacity = capacity;
    this.refillPerSec = refillPerSec;
    this.now = now;
    this.tokens = capacity;
    this.last = now();
  }

  take(n = 1) {
    const t = this.now();
    const elapsed = Math.max(0, t - this.last) / 1000;
    this.last = t;
    this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.refillPerSec);
    if (this.tokens < n) return false;
    this.tokens -= n;
    return true;
  }
}

/** Sliding-window failure circuit breaker. */
export class CircuitBreaker {
  constructor({ threshold = 32, windowMs = 10_000, cooldownMs = 30_000, now = nowMs }) {
    this.threshold = threshold;
    this.windowMs = windowMs;
    this.cooldownMs = cooldownMs;
    this.now = now;
    this.failures = [];
    this.openUntil = 0;
  }

  allow() {
    return this.now() >= this.openUntil;
  }

  recordFailure() {
    const t = this.now();
    this.failures = this.failures.filter((x) => t - x < this.windowMs);
    this.failures.push(t);
    if (this.failures.length >= this.threshold) {
      this.openUntil = t + this.cooldownMs;
      this.failures = [];
      return true; // tripped
    }
    return false;
  }

  reset() {
    this.failures = [];
    this.openUntil = 0;
  }
}

/** Append-only, hash-chained audit log. */
export class AuditLog {
  constructor(secret, { capacity = 10_000, now = nowMs } = {}) {
    this.secret = Buffer.from(toBytes(secret));
    assert(this.secret.length >= 16, ERR.KEY, 'audit secret must be at least 16 bytes');
    this.capacity = capacity;
    this.now = now;
    this.entries = [];
    this.seq = 0;
    this.head = '00'.repeat(32);
  }

  append(kind, fields = {}) {
    const entry = {
      seq: this.seq,
      ts: this.now(),
      kind,
      ...fields,
    };
    const body = Buffer.from(JSON.stringify(entry), 'utf8');
    const mac = hmacSha256(this.secret, Buffer.from(this.head, 'hex'), body).toString('hex');
    const full = { ...entry, prev: this.head, mac };
    this.head = mac;
    this.seq += 1;
    this.entries.push(full);
    if (this.entries.length > this.capacity) this.entries.shift();
    return full;
  }

  /** Recompute the chain; returns {ok, brokenAt}. */
  verify() {
    let prev = '00'.repeat(32);
    const first = this.entries.length > 0 ? this.entries[0].seq : 0;
    if (first > 0) prev = this.entries[0].prev;
    for (const e of this.entries) {
      const { prev: claimed, mac, ...rest } = e;
      if (claimed !== prev) return { ok: false, brokenAt: e.seq };
      const body = Buffer.from(JSON.stringify(rest), 'utf8');
      const expect = hmacSha256(this.secret, Buffer.from(prev, 'hex'), body).toString('hex');
      if (expect !== mac) return { ok: false, brokenAt: e.seq };
      prev = mac;
    }
    return { ok: true, brokenAt: null };
  }
}

const DEFAULT_POLICY = Object.freeze({
  purposes: null, // null = any; array = allowlist
  maxOpsPerMinute: 600,
  burst: 120,
  maxBytesPerOp: 8 * 1024 * 1024,
  maxTotalBytes: 1024 * 1024 * 1024,
  maxKeyAgeMs: 24 * 60 * 60 * 1000,
  maxAuthFailures: 5,
  lockoutMs: 60_000,
  canary: false,
});

/**
 * Holds keys and enforces policy. Raw key bytes never leave this object.
 */
export class Keyring {
  constructor({ audit, now = nowMs, onAlert = () => {} } = {}) {
    this.audit = audit ?? new AuditLog(randomBytes(32), { now });
    this.now = now;
    this.onAlert = onAlert;
    this.keys = new Map();
    this.breaker = new CircuitBreaker({ now });
  }

  add(id, masterKey, policy = {}) {
    assert(typeof id === 'string' && id.length > 0, ERR.POLICY, 'capability id required');
    assert(!this.keys.has(id), ERR.POLICY, `capability ${id} already exists`);
    const p = { ...DEFAULT_POLICY, ...policy };
    this.keys.set(id, {
      sealKey: new SealKey(masterKey),
      policy: p,
      bucket: new TokenBucket({ capacity: p.burst, refillPerSec: p.maxOpsPerMinute / 60, now: this.now }),
      bytes: 0,
      ops: 0,
      authFailures: 0,
      lockedUntil: 0,
      createdAt: this.now(),
      revoked: false,
    });
    this.audit.append('key.add', { id, canary: p.canary === true });
    return id;
  }

  /** Register a decoy capability: usage is logged as a critical alert. */
  addCanary(id, purposeLabel = 'canary') {
    const key = sha256(Buffer.from(`canary:${id}:${purposeLabel}`));
    return this.add(id, key, { canary: true, purposes: [purposeLabel], maxTotalBytes: 1 << 30 });
  }

  revoke(id) {
    const k = this.#get(id);
    k.revoked = true;
    k.sealKey.destroy();
    this.audit.append('key.revoke', { id });
  }

  rotate(id, newKey) {
    const k = this.#get(id);
    k.sealKey.destroy();
    k.sealKey = new SealKey(newKey);
    k.createdAt = this.now();
    k.bytes = 0;
    k.ops = 0;
    k.authFailures = 0;
    this.audit.append('key.rotate', { id });
    return id;
  }

  #get(id) {
    const k = this.keys.get(id);
    if (k === undefined) throw new VantaError(ERR.KEY, `unknown capability ${id}`);
    return k;
  }

  #precheck(k, id, purpose, bytes) {
    if (!this.breaker.allow()) {
      this.audit.append('deny.breaker', { id });
      throw new VantaError(ERR.POLICY, 'circuit breaker open');
    }
    if (k.revoked) throw new VantaError(ERR.POLICY, 'capability revoked');
    if (this.now() < k.lockedUntil) {
      this.audit.append('deny.locked', { id });
      throw new VantaError(ERR.POLICY, 'capability locked after authentication failures');
    }
    if (k.policy.maxKeyAgeMs > 0 && this.now() - k.createdAt > k.policy.maxKeyAgeMs) {
      this.audit.append('deny.age', { id });
      throw new VantaError(ERR.POLICY, 'key exceeds its cryptoperiod; rotate it');
    }
    if (k.policy.purposes !== null && !k.policy.purposes.includes(purpose)) {
      this.audit.append('deny.purpose', { id, purpose });
      throw new VantaError(ERR.POLICY, `purpose "${purpose}" not permitted for this capability`);
    }
    if (bytes > k.policy.maxBytesPerOp) {
      this.audit.append('deny.size', { id, bytes });
      throw new VantaError(ERR.POLICY, 'operation exceeds per-operation byte limit');
    }
    if (k.bytes + bytes > k.policy.maxTotalBytes) {
      this.audit.append('deny.budget', { id, bytes });
      throw new VantaError(ERR.POLICY, 'capability byte budget exhausted');
    }
    if (!k.bucket.take(1)) {
      this.audit.append('deny.rate', { id });
      throw new VantaError(ERR.POLICY, 'capability rate limit exceeded');
    }
  }

  seal(id, plaintext, { purpose = 'default', aad = EMPTY } = {}) {
    const k = this.#get(id);
    const pt = toBytes(plaintext);
    this.#precheck(k, id, purpose, pt.length);
    if (k.policy.canary) {
      // Canaries still emit well-formed ciphertext, but the material is a
      // decoy: this detects an agent that is using a stolen capability.
      this.onAlert({ severity: 'critical', kind: 'canary.use', id, op: 'seal' });
    }
    const env = k.sealKey.seal(pt, intentAad(purpose, aad));
    k.bytes += pt.length;
    k.ops += 1;
    this.audit.append('seal', { id, purpose, bytes: pt.length });
    return env;
  }

  open(id, envelope, { purpose = 'default', aad = EMPTY } = {}) {
    const k = this.#get(id);
    const env = toBytes(envelope);
    this.#precheck(k, id, purpose, env.length);
    if (k.policy.canary) {
      this.onAlert({ severity: 'critical', kind: 'canary.use', id, op: 'open' });
      const len = Math.max(0, env.length - 80);
      return hkdfSha256(sha256(k.sealKey.kEnc, env), EMPTY, Buffer.from('canary'), len);
    }
    try {
      const pt = k.sealKey.open(env, intentAad(purpose, aad));
      k.bytes += pt.length;
      k.ops += 1;
      k.authFailures = 0;
      this.audit.append('open', { id, purpose, bytes: pt.length });
      return pt;
    } catch (err) {
      if (err instanceof VantaError && err.code === ERR.AUTH) {
        k.authFailures += 1;
        const tripped = this.breaker.recordFailure();
        this.audit.append('auth.fail', { id, purpose, count: k.authFailures, tripped });
        if (k.authFailures >= k.policy.maxAuthFailures) {
          k.lockedUntil = this.now() + k.policy.lockoutMs;
          this.audit.append('key.lock', { id });
          this.onAlert({ severity: 'high', kind: 'auth.lockout', id });
        }
        if (tripped) this.onAlert({ severity: 'high', kind: 'breaker.open' });
      }
      throw err;
    }
  }

  stats(id) {
    const k = this.#get(id);
    return {
      id,
      ops: k.ops,
      bytes: k.bytes,
      authFailures: k.authFailures,
      locked: this.now() < k.lockedUntil,
      ageMs: this.now() - k.createdAt,
      canary: k.policy.canary === true,
      revoked: k.revoked,
    };
  }
}

// ---------------------------------------------------------------------------
// Split custody (Shamir secret sharing over GF(2^8)).
// ---------------------------------------------------------------------------

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(function buildTables() {
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = x;
    LOG[x] = i;
    const hi = (x << 1) & 0xff;
    const xtime = hi ^ (x & 0x80 ? 0x1b : 0);
    x ^= xtime; // multiply by generator 3
  }
  for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function gfDiv(a, b) {
  assert(b !== 0, ERR.RANGE, 'division by zero in GF(256)');
  if (a === 0) return 0;
  return EXP[(LOG[a] - LOG[b] + 255) % 255];
}

function gfInv(a) {
  assert(a !== 0, ERR.RANGE, 'inverse of zero');
  return EXP[255 - LOG[a]];
}

/**
 * Split `secret` into `n` shares, any `k` of which reconstruct it.
 * @returns {Buffer[]} each share is [x(1) || y(bytes)]
 */
export function shamirSplit(secret, n, k, rng = randomBytes) {
  const s = toBytes(secret);
  assert(s.length > 0, ERR.RANGE, 'secret must be non-empty');
  assert(k >= 2 && k <= n && n <= 255, ERR.RANGE, 'require 2 <= k <= n <= 255');
  const shares = [];
  for (let i = 1; i <= n; i += 1) shares.push(Buffer.alloc(1 + s.length));
  for (let b = 0; b < s.length; b += 1) {
    const coeffs = [s[b]];
    const r = rng(k - 1);
    for (let j = 0; j < k - 1; j += 1) coeffs.push(r[j]);
    for (let i = 1; i <= n; i += 1) {
      let y = 0;
      for (let j = coeffs.length - 1; j >= 0; j -= 1) y = gfMul(y, i) ^ coeffs[j];
      shares[i - 1][0] = i;
      shares[i - 1][1 + b] = y;
    }
  }
  return shares;
}

/** Reconstruct a secret from any k shares. */
export function shamirCombine(shares) {
  const list = shares.map((sh) => toBytes(sh));
  assert(list.length >= 2, ERR.RANGE, 'need at least two shares');
  const len = list[0].length - 1;
  for (const sh of list) {
    assert(sh.length === len + 1, ERR.RANGE, 'inconsistent share lengths');
    assert(sh[0] !== 0, ERR.RANGE, 'invalid share index');
  }
  const out = Buffer.alloc(len);
  for (let b = 0; b < len; b += 1) {
    let acc = 0;
    for (let i = 0; i < list.length; i += 1) {
      const xi = list[i][0];
      let num = 1;
      let den = 1;
      for (let j = 0; j < list.length; j += 1) {
        if (i === j) continue;
        const xj = list[j][0];
        assert(xi !== xj, ERR.RANGE, 'duplicate share index');
        num = gfMul(num, xj);
        den = gfMul(den, xj ^ xi);
      }
      acc ^= gfMul(list[i][1 + b], gfMul(num, gfInv(den)));
    }
    out[b] = acc;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Proof-of-work admission control (mass-coordination defence).
// ---------------------------------------------------------------------------

export function hashcash(challenge, counter) {
  return sha256(toBytes(challenge), u64be(counter));
}

export function leadingZeroBits(buf) {
  let bits = 0;
  for (const byte of toBytes(buf)) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

/** Client-side: find a counter meeting `difficultyBits` of work. */
export function solveChallenge(challenge, difficultyBits, { maxIterations = 1 << 28 } = {}) {
  assert(difficultyBits >= 0 && difficultyBits <= 32, ERR.RANGE, 'difficulty must be 0..32 bits');
  for (let c = 0; c < maxIterations; c += 1) {
    if (leadingZeroBits(hashcash(challenge, c)) >= difficultyBits) return c;
  }
  throw new VantaError(ERR.POLICY, 'proof-of-work budget exhausted');
}

export function verifySolution(challenge, counter, difficultyBits) {
  return leadingZeroBits(hashcash(challenge, counter)) >= difficultyBits;
}

/**
 * Admission gate for unauthenticated handshakes. Escalates the required work
 * as load rises, so a coordinated flood costs the attacker super-linearly
 * while a single honest client still pays only a few milliseconds.
 */
export class AdmissionGate {
  constructor({
    baseBits = 16,
    maxBits = 24,
    windowMs = 1000,
    capacityPerWindow = 200,
    now = nowMs,
  } = {}) {
    this.baseBits = baseBits;
    this.maxBits = maxBits;
    this.windowMs = windowMs;
    this.capacityPerWindow = capacityPerWindow;
    this.now = now;
    this.windowStart = now();
    this.count = 0;
    this.secret = randomBytes(32);
    // Tickets are single-use: a valid PoW solution must not be replayable for
    // the rest of its 30-second lifetime.
    this.used = new Map();
  }

  #roll() {
    const t = this.now();
    if (t - this.windowStart >= this.windowMs) {
      this.windowStart = t;
      this.count = 0;
    }
    this.count += 1;
    return this.count;
  }

  /** Current difficulty, rising with observed request pressure. */
  difficulty() {
    const n = this.#roll();
    if (n <= this.capacityPerWindow) return this.baseBits;
    const excess = Math.min(1, (n - this.capacityPerWindow) / this.capacityPerWindow);
    return Math.round(this.baseBits + excess * (this.maxBits - this.baseBits));
  }

  issue() {
    const challenge = randomBytes(32);
    const bits = this.difficulty();
    const expires = this.now() + 30_000;
    const mac = hmacSha256(this.secret, challenge, u32be(bits), u64be(expires));
    return { challenge, bits, expires, mac };
  }

  verify(ticket, counter) {
    const { challenge, bits, expires, mac } = ticket;
    if (this.now() > Number(expires)) return { ok: false, reason: 'expired' };
    const expect = hmacSha256(this.secret, challenge, u32be(bits), u64be(expires));
    if (!Buffer.from(mac).equals(expect)) return { ok: false, reason: 'bad-ticket' };
    const key = `${Buffer.from(challenge).toString('hex')}:${counter}`;
    if (this.used.has(key)) return { ok: false, reason: 'reused' };
    if (!verifySolution(challenge, counter, bits)) return { ok: false, reason: 'insufficient-work' };
    this.used.set(key, Number(expires));
    if (this.used.size > 100_000) {
      const now = this.now();
      for (const [k, exp] of this.used) if (exp < now) this.used.delete(k);
    }
    return { ok: true };
  }
}
