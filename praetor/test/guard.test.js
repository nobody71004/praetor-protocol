import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AdmissionGate,
  AuditLog,
  CircuitBreaker,
  ERR,
  Keyring,
  TokenBucket,
  PraetorError,
  leadingZeroBits,
  randomBytes,
  shamirCombine,
  shamirSplit,
  solveChallenge,
  verifySolution,
} from '../src/index.js';

function clock(start = 1_000_000) {
  let t = start;
  const now = () => t;
  now.advance = (ms) => {
    t += ms;
  };
  return now;
}

test('token bucket refills over time', () => {
  const now = clock();
  const b = new TokenBucket({ capacity: 3, refillPerSec: 1, now });
  assert.equal(b.take(3), true);
  assert.equal(b.take(1), false);
  now.advance(1000);
  assert.equal(b.take(1), true);
});

test('purpose binding stops capability escalation', () => {
  const now = clock();
  const alerts = [];
  const kr = new Keyring({ now, onAlert: (a) => alerts.push(a) });
  kr.add('agent-config', randomBytes(32), { purposes: ['read:config'] });
  const env = kr.seal('agent-config', Buffer.from('db password'), { purpose: 'read:config' });
  assert.deepEqual(kr.open('agent-config', env, { purpose: 'read:config' }), Buffer.from('db password'));
  assert.throws(
    () => kr.open('agent-config', env, { purpose: 'read:customers' }),
    (e) => e instanceof PraetorError && e.code === ERR.POLICY,
  );
  // Even with the right purpose, a different AAD fails.
  assert.throws(() => kr.open('agent-config', env, { purpose: 'read:config', aad: Buffer.from('x') }));
});

test('byte limits and the total budget are enforced', () => {
  const now = clock();
  const kr = new Keyring({ now });
  kr.add('k', randomBytes(32), { maxBytesPerOp: 10, maxTotalBytes: 15 });
  assert.ok(kr.seal('k', Buffer.alloc(10)));
  assert.throws(() => kr.seal('k', Buffer.alloc(11)), /byte limit/);
  assert.throws(() => kr.seal('k', Buffer.alloc(6)), /budget/);
});

test('rate limits, cooldown and cryptoperiod are enforced', () => {
  const now = clock();
  const kr = new Keyring({ now });
  kr.add('r', randomBytes(32), { burst: 1, maxOpsPerMinute: 60 });
  assert.ok(kr.seal('r', Buffer.alloc(5)));
  assert.throws(() => kr.seal('r', Buffer.alloc(5)), /rate limit/);
  now.advance(1500);
  assert.ok(kr.seal('r', Buffer.alloc(5)));

  kr.add('a', randomBytes(32), { maxKeyAgeMs: 5000 });
  now.advance(6000);
  assert.throws(() => kr.seal('a', Buffer.alloc(1)), /cryptoperiod/);
});

test('repeated forgeries lock the capability and trip the breaker', () => {
  const now = clock();
  const alerts = [];
  const kr = new Keyring({ now, onAlert: (a) => alerts.push(a) });
  kr.add('k', randomBytes(32), { maxAuthFailures: 3, lockoutMs: 1000 });
  const env = kr.seal('k', Buffer.from('x'));
  const bad = Buffer.from(env);
  bad[0] ^= 1;
  for (let i = 0; i < 3; i += 1) assert.throws(() => kr.open('k', bad));
  assert.equal(kr.stats('k').locked, true);
  assert.ok(alerts.some((a) => a.kind === 'auth.lockout'));
  assert.throws(() => kr.open('k', env), /locked/);
  now.advance(1001);
  assert.deepEqual(kr.open('k', env), Buffer.from('x'));
});

test('canary capabilities return decoys and alert', () => {
  const now = clock();
  const alerts = [];
  const kr = new Keyring({ now, onAlert: (a) => alerts.push(a) });
  kr.addCanary('honeypot', 'read:prod');
  const decoy = kr.seal('honeypot', Buffer.from('nothing real'), { purpose: 'read:prod' });
  const out = kr.open('honeypot', decoy, { purpose: 'read:prod' });
  assert.equal(out.length, decoy.length - 80);
  assert.ok(!out.includes(Buffer.from('nothing real')));
  assert.equal(alerts.filter((a) => a.kind === 'canary.use').length, 2);
  assert.ok(alerts.every((a) => a.severity === 'critical'));
});

test('audit chain detects tampering', () => {
  const log = new AuditLog(randomBytes(32), { now: clock() });
  log.append('open', { id: 'a' });
  log.append('open', { id: 'b' });
  assert.equal(log.verify().ok, true);
  log.entries[0].kind = 'rewritten';
  const v = log.verify();
  assert.equal(v.ok, false);
  assert.equal(v.brokenAt, 0);
});

test('shamir split needs exactly k shares', () => {
  const secret = randomBytes(32);
  const shares = shamirSplit(secret, 5, 3, (n) => Buffer.alloc(n, 0x5a));
  assert.equal(shares.length, 5);
  assert.deepEqual(shamirCombine(shares.slice(0, 3)), secret);
  assert.deepEqual(shamirCombine([shares[0], shares[2], shares[4]]), secret);
  assert.notDeepEqual(shamirCombine(shares.slice(0, 2)), secret);
  assert.throws(() => shamirCombine([shares[0], shares[0]]), /duplicate/);
  assert.throws(() => shamirSplit(secret, 3, 4), /k <= n/);
});

test('proof of work is verifiable and difficulty-bound', () => {
  const challenge = randomBytes(32);
  const bits = 8;
  const counter = solveChallenge(challenge, bits);
  assert.equal(verifySolution(challenge, counter, bits), true);
  if (counter > 0) {
    assert.equal(verifySolution(challenge, counter - 1, bits), false);
  }
  assert.ok(leadingZeroBits(Buffer.alloc(4)) === 32);
});

test('admission gate escalates under coordination pressure', () => {
  const now = clock();
  const gate = new AdmissionGate({ now, baseBits: 4, maxBits: 12, capacityPerWindow: 2, windowMs: 1000 });
  const d1 = gate.issue();
  assert.equal(d1.bits, 4);
  gate.issue();
  const d3 = gate.issue();
  assert.ok(d3.bits > 4);
  const counter = solveChallenge(d3.challenge, d3.bits);
  assert.equal(gate.verify(d3, counter).ok, true);
  assert.deepEqual(gate.verify(d3, counter), { ok: false, reason: 'reused' });
  assert.deepEqual(gate.verify({ ...d3, expires: 0 }, counter), { ok: false, reason: 'expired' });
  assert.equal(gate.verify({ ...d3, mac: Buffer.alloc(32) }, counter).ok, false);
});

test('circuit breaker opens and cools down', () => {
  const now = clock();
  const cb = new CircuitBreaker({ threshold: 2, windowMs: 100, cooldownMs: 500, now });
  assert.equal(cb.allow(), true);
  cb.recordFailure();
  assert.equal(cb.recordFailure(), true);
  assert.equal(cb.allow(), false);
  now.advance(501);
  assert.equal(cb.allow(), true);
});
