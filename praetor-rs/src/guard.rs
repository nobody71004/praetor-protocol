//! PRAETOR/GUARD — capability enforcement for untrusted callers.
//!
//! Mirrors the JavaScript guard layer: purpose-bound capabilities, quotas,
//! authentication-failure lockouts, a circuit breaker, canaries, a
//! tamper-evident audit chain, Shamir split custody and proof-of-work
//! admission. Key bytes never leave the `Vault`.

use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;

use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::aead::SealKey;
use crate::error::{Error, Result};
use crate::util::{ct_eq, hkdf_sha256, hmac_sha256, random_array, sha256, u16be, u32be, u64be};

const LABEL_INTENT: &[u8] = b"PRAETOR/1/intent";
pub const ENVELOPE_OVERHEAD: usize = 80;

pub fn intent_aad(purpose: &str, aad: &[u8]) -> Result<Vec<u8>> {
    let p = purpose.as_bytes();
    if p.is_empty() || p.len() > u16::MAX as usize {
        return Err(Error::Policy);
    }
    let mut out = Vec::with_capacity(LABEL_INTENT.len() + 2 + p.len() + aad.len());
    out.extend_from_slice(LABEL_INTENT);
    out.extend_from_slice(&u16be(p.len() as u16));
    out.extend_from_slice(p);
    out.extend_from_slice(aad);
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct Alert {
    pub severity: &'static str,
    pub kind: &'static str,
    pub id: String,
}

// ---------------------------------------------------------------------------
// Token bucket / circuit breaker
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_ms: f64,
    tokens: f64,
    last_ms: u64,
}

impl TokenBucket {
    pub fn new(capacity: u32, per_minute: u32, now_ms: u64) -> Self {
        Self {
            capacity: capacity as f64,
            refill_per_ms: per_minute as f64 / 60_000.0,
            tokens: capacity as f64,
            last_ms: now_ms,
        }
    }

    pub fn take(&mut self, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_ms) as f64;
        self.last_ms = now_ms;
        self.tokens = (self.tokens + elapsed * self.refill_per_ms).min(self.capacity);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

#[derive(Clone, Debug)]
pub struct CircuitBreaker {
    threshold: usize,
    window_ms: u64,
    cooldown_ms: u64,
    failures: VecDeque<u64>,
    open_until: u64,
}

impl CircuitBreaker {
    pub fn new(threshold: usize, window_ms: u64, cooldown_ms: u64) -> Self {
        Self { threshold, window_ms, cooldown_ms, failures: VecDeque::new(), open_until: 0 }
    }

    pub fn allow(&self, now_ms: u64) -> bool {
        now_ms >= self.open_until
    }

    pub fn record_failure(&mut self, now_ms: u64) -> bool {
        while let Some(front) = self.failures.front() {
            if now_ms.saturating_sub(*front) > self.window_ms {
                self.failures.pop_front();
            } else {
                break;
            }
        }
        self.failures.push_back(now_ms);
        if self.failures.len() >= self.threshold {
            self.open_until = now_ms + self.cooldown_ms;
            self.failures.clear();
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Audit chain
// ---------------------------------------------------------------------------

pub struct AuditLog {
    secret: [u8; 32],
    pub entries: Vec<Value>,
    head: String,
    seq: u64,
}

impl AuditLog {
    pub fn new(secret: &[u8]) -> Result<Self> {
        if secret.len() < 16 {
            return Err(Error::Key);
        }
        let mut s = [0u8; 32];
        let n = secret.len().min(32);
        s[..n].copy_from_slice(&secret[..n]);
        Ok(Self { secret: s, entries: Vec::new(), head: "00".repeat(32), seq: 0 })
    }

    fn body(seq: u64, ts: u64, kind: &str, meta: &Value) -> String {
        format!("{}\n{}\n{}\n{}", seq, ts, kind, meta)
    }

    pub fn append(&mut self, kind: &str, ts: u64, meta: Value) -> Value {
        let body = Self::body(self.seq, ts, kind, &meta);
        let mut prev_bytes = Vec::with_capacity(32);
        for i in (0..self.head.len()).step_by(2) {
            prev_bytes.push(u8::from_str_radix(&self.head[i..i + 2], 16).unwrap_or(0));
        }
        let mac = hex::encode(hmac_sha256(&self.secret, &[&prev_bytes, body.as_bytes()]));
        let entry = json!({
            "seq": self.seq,
            "ts": ts,
            "kind": kind,
            "meta": meta,
            "prev": self.head,
            "mac": mac,
        });
        self.head = mac;
        self.seq += 1;
        self.entries.push(entry.clone());
        entry
    }

    pub fn verify(&self) -> bool {
        let mut prev = "00".repeat(32);
        for e in &self.entries {
            let seq = e["seq"].as_u64().unwrap_or(u64::MAX);
            let ts = e["ts"].as_u64().unwrap_or(0);
            let kind = e["kind"].as_str().unwrap_or("");
            let meta = &e["meta"];
            if e["prev"].as_str().unwrap_or("") != prev {
                return false;
            }
            let body = Self::body(seq, ts, kind, meta);
            let mut prev_bytes = Vec::with_capacity(32);
            for i in (0..prev.len()).step_by(2) {
                prev_bytes.push(u8::from_str_radix(&prev[i..i + 2], 16).unwrap_or(0));
            }
            let expect = hex::encode(hmac_sha256(&self.secret, &[&prev_bytes, body.as_bytes()]));
            if e["mac"].as_str().unwrap_or("") != expect {
                return false;
            }
            prev = expect;
        }
        true
    }

    pub fn head(&self) -> &str {
        &self.head
    }
}

// ---------------------------------------------------------------------------
// Policy and vault
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Policy {
    pub purposes: Option<Vec<String>>,
    pub max_ops_per_minute: u32,
    pub burst: u32,
    pub max_bytes_per_op: usize,
    pub max_total_bytes: u64,
    pub max_key_age_ms: u64,
    pub max_auth_failures: u32,
    pub lockout_ms: u64,
    pub canary: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            purposes: None,
            max_ops_per_minute: 600,
            burst: 120,
            max_bytes_per_op: 8 * 1024 * 1024,
            max_total_bytes: 1 << 30,
            max_key_age_ms: 24 * 60 * 60 * 1000,
            max_auth_failures: 5,
            lockout_ms: 60_000,
            canary: false,
        }
    }
}

struct Entry {
    seal: SealKey,
    policy: Policy,
    bucket: TokenBucket,
    bytes: u64,
    ops: u64,
    auth_failures: u32,
    locked_until: u64,
    created_ms: u64,
    revoked: bool,
}

pub struct Vault {
    keys: HashMap<String, Entry>,
    pub audit: AuditLog,
    breaker: CircuitBreaker,
    pub alerts: Vec<Alert>,
}

impl Vault {
    pub fn new(audit_secret: &[u8]) -> Result<Self> {
        Ok(Self {
            keys: HashMap::new(),
            audit: AuditLog::new(audit_secret)?,
            breaker: CircuitBreaker::new(32, 10_000, 30_000),
            alerts: Vec::new(),
        })
    }

    pub fn add(&mut self, id: &str, master: &[u8], policy: Policy, now_ms: u64) -> Result<()> {
        if self.keys.contains_key(id) {
            return Err(Error::Policy);
        }
        let bucket = TokenBucket::new(policy.burst, policy.max_ops_per_minute, now_ms);
        self.keys.insert(
            id.to_string(),
            Entry {
                seal: SealKey::new(master)?,
                policy,
                bucket,
                bytes: 0,
                ops: 0,
                auth_failures: 0,
                locked_until: 0,
                created_ms: now_ms,
                revoked: false,
            },
        );
        self.audit.append("key.add", now_ms, json!({ "id": id }));
        Ok(())
    }

    pub fn add_canary(&mut self, id: &str, purpose: &str, now_ms: u64) -> Result<()> {
        let mut material = [0u8; 32];
        let h = sha256(&[b"canary", id.as_bytes(), purpose.as_bytes()]);
        material.copy_from_slice(&h);
        let policy = Policy { canary: true, purposes: Some(vec![purpose.to_string()]), ..Policy::default() };
        self.add(id, &material, policy, now_ms)?;
        material.zeroize();
        Ok(())
    }

    fn precheck(&mut self, id: &str, purpose: &str, bytes: usize, now_ms: u64) -> Result<()> {
        if !self.breaker.allow(now_ms) {
            self.audit.append("deny.breaker", now_ms, json!({ "id": id }));
            return Err(Error::Policy);
        }
        let entry = self.keys.get_mut(id).ok_or(Error::Key)?;
        if entry.revoked {
            return Err(Error::Policy);
        }
        if now_ms < entry.locked_until {
            return Err(Error::Policy);
        }
        if entry.policy.max_key_age_ms > 0 && now_ms.saturating_sub(entry.created_ms) > entry.policy.max_key_age_ms {
            self.audit.append("deny.age", now_ms, json!({ "id": id }));
            return Err(Error::Policy);
        }
        if let Some(list) = &entry.policy.purposes {
            if !list.iter().any(|p| p == purpose) {
                self.audit.append("deny.purpose", now_ms, json!({ "id": id, "purpose": purpose }));
                return Err(Error::Policy);
            }
        }
        if bytes > entry.policy.max_bytes_per_op {
            return Err(Error::Policy);
        }
        if entry.bytes + bytes as u64 > entry.policy.max_total_bytes {
            return Err(Error::Policy);
        }
        if !entry.bucket.take(now_ms) {
            self.audit.append("deny.rate", now_ms, json!({ "id": id }));
            return Err(Error::Policy);
        }
        Ok(())
    }

    pub fn seal(&mut self, id: &str, pt: &[u8], purpose: &str, aad: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        self.precheck(id, purpose, pt.len(), now_ms)?;
        let aad = intent_aad(purpose, aad)?;
        let canary = self.keys[id].policy.canary;
        if canary {
            self.alerts.push(Alert { severity: "critical", kind: "canary.use", id: id.into() });
        }
        let env = self.keys[id].seal.seal_random(pt, &aad)?;
        let entry = self.keys.get_mut(id).unwrap();
        entry.bytes += pt.len() as u64;
        entry.ops += 1;
        self.audit.append("seal", now_ms, json!({ "id": id, "purpose": purpose, "bytes": pt.len() }));
        Ok(env)
    }

    pub fn open(&mut self, id: &str, env: &[u8], purpose: &str, aad: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        self.precheck(id, purpose, env.len(), now_ms)?;
        let aad = intent_aad(purpose, aad)?;
        let canary = self.keys[id].policy.canary;
        if canary {
            self.alerts.push(Alert { severity: "critical", kind: "canary.use", id: id.into() });
            let len = env.len().saturating_sub(ENVELOPE_OVERHEAD);
            let seed = sha256(&[env]);
            let mut out = Vec::with_capacity(len);
            while out.len() < len {
                out.extend_from_slice(&seed);
            }
            out.truncate(len);
            return Ok(out);
        }
        let result = self.keys[id].seal.open(env, &aad, false);
        match result {
            Ok(pt) => {
                let entry = self.keys.get_mut(id).unwrap();
                entry.bytes += pt.len() as u64;
                entry.ops += 1;
                entry.auth_failures = 0;
                self.audit.append("open", now_ms, json!({ "id": id, "purpose": purpose, "bytes": pt.len() }));
                Ok(pt)
            }
            Err(e) => {
                let tripped;
                let locked;
                {
                    let entry = self.keys.get_mut(id).unwrap();
                    entry.auth_failures += 1;
                    tripped = self.breaker.record_failure(now_ms);
                    locked = entry.auth_failures >= entry.policy.max_auth_failures;
                    if locked {
                        entry.locked_until = now_ms + entry.policy.lockout_ms;
                    }
                }
                self.audit.append("auth.fail", now_ms, json!({ "id": id, "count": self.keys[id].auth_failures }));
                if locked {
                    self.alerts.push(Alert { severity: "high", kind: "auth.lockout", id: id.into() });
                }
                if tripped {
                    self.alerts.push(Alert { severity: "high", kind: "breaker.open", id: id.into() });
                }
                Err(e)
            }
        }
    }

    pub fn stats(&self, id: &str) -> Result<Value> {
        let e = self.keys.get(id).ok_or(Error::Key)?;
        Ok(json!({
            "id": id,
            "ops": e.ops,
            "bytes": e.bytes,
            "authFailures": e.auth_failures,
            "canary": e.policy.canary,
            "revoked": e.revoked,
        }))
    }
}

// ---------------------------------------------------------------------------
// Shamir split custody over GF(2^8)
// ---------------------------------------------------------------------------

fn tables() -> &'static ([u8; 512], [u8; 256]) {
    static T: OnceLock<([u8; 512], [u8; 256])> = OnceLock::new();
    T.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u8 = 1;
        for i in 0..255 {
            exp[i] = x;
            log[x as usize] = i as u8;
            let hi = x.wrapping_shl(1);
            let xtime = if x & 0x80 != 0 { hi ^ 0x1b } else { hi };
            x ^= xtime;
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        (exp, log)
    })
}

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = tables();
    exp[log[a as usize] as usize + log[b as usize] as usize]
}

fn gf_inv(a: u8) -> Result<u8> {
    if a == 0 {
        return Err(Error::Range);
    }
    let (exp, log) = tables();
    Ok(exp[255 - log[a as usize] as usize])
}

pub fn shamir_split(secret: &[u8], n: u8, k: u8) -> Result<Vec<Vec<u8>>> {
    if secret.is_empty() || k < 2 || k > n {
        return Err(Error::Range);
    }
    let mut shares = vec![vec![0u8; secret.len() + 1]; n as usize];
    for (i, s) in shares.iter_mut().enumerate() {
        s[0] = (i + 1) as u8;
    }
    for (b, &byte) in secret.iter().enumerate() {
        let mut coeffs = vec![byte];
        for _ in 0..k - 1 {
            coeffs.push(random_array::<1>()[0]);
        }
        for i in 1..=n {
            let mut y = 0u8;
            for &c in coeffs.iter().rev() {
                y = gf_mul(y, i) ^ c;
            }
            shares[(i - 1) as usize][1 + b] = y;
        }
    }
    Ok(shares)
}

pub fn shamir_combine(shares: &[Vec<u8>]) -> Result<Vec<u8>> {
    if shares.len() < 2 {
        return Err(Error::Range);
    }
    let len = shares[0].len() - 1;
    for s in shares {
        if s.len() != len + 1 || s[0] == 0 {
            return Err(Error::Range);
        }
    }
    let mut out = vec![0u8; len];
    for b in 0..len {
        let mut acc = 0u8;
        for i in 0..shares.len() {
            let xi = shares[i][0];
            let mut num = 1u8;
            let mut den = 1u8;
            for j in 0..shares.len() {
                if i == j {
                    continue;
                }
                let xj = shares[j][0];
                if xi == xj {
                    return Err(Error::Range);
                }
                num = gf_mul(num, xj);
                den = gf_mul(den, xj ^ xi);
            }
            acc ^= gf_mul(shares[i][1 + b], gf_mul(num, gf_inv(den)?));
        }
        out[b] = acc;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Proof-of-work admission
// ---------------------------------------------------------------------------

pub fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut bits = 0;
    for &b in bytes {
        if b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    bits
}

pub fn hashcash(challenge: &[u8], counter: u64) -> [u8; 32] {
    sha256(&[challenge, &u64be(counter)])
}

pub fn solve_challenge(challenge: &[u8], bits: u32) -> Result<u64> {
    if bits > 32 {
        return Err(Error::Range);
    }
    for c in 0..(1u64 << 32) {
        if leading_zero_bits(&hashcash(challenge, c)) >= bits {
            return Ok(c);
        }
    }
    Err(Error::Policy)
}

pub fn verify_solution(challenge: &[u8], counter: u64, bits: u32) -> bool {
    leading_zero_bits(&hashcash(challenge, counter)) >= bits
}

pub struct AdmissionGate {
    base_bits: u32,
    max_bits: u32,
    capacity: u32,
    window_ms: u64,
    window_start: u64,
    count: u32,
    secret: [u8; 32],
    used: HashMap<String, u64>,
}

impl AdmissionGate {
    pub fn new(base_bits: u32, max_bits: u32, capacity: u32) -> Self {
        Self {
            base_bits,
            max_bits,
            capacity,
            window_ms: 1000,
            window_start: 0,
            count: 0,
            secret: random_array(),
            used: HashMap::new(),
        }
    }

    fn roll(&mut self, now_ms: u64) -> u32 {
        if now_ms.saturating_sub(self.window_start) >= self.window_ms {
            self.window_start = now_ms;
            self.count = 0;
        }
        self.count += 1;
        self.count
    }

    pub fn difficulty(&mut self, now_ms: u64) -> u32 {
        let n = self.roll(now_ms);
        if n <= self.capacity {
            return self.base_bits;
        }
        let excess = ((n - self.capacity) as f64 / self.capacity as f64).min(1.0);
        (self.base_bits as f64 + excess * (self.max_bits - self.base_bits) as f64).round() as u32
    }

    pub fn issue(&mut self, now_ms: u64) -> Value {
        let challenge = random_array::<32>();
        let bits = self.difficulty(now_ms);
        let expires = now_ms + 30_000;
        let mac = hmac_sha256(&self.secret, &[&challenge, &u32be(bits), &u64be(expires)]);
        json!({
            "challenge": hex::encode(challenge),
            "bits": bits,
            "expires": expires,
            "mac": hex::encode(mac),
        })
    }

    pub fn verify(&mut self, ticket: &Value, counter: u64, now_ms: u64) -> bool {
        let challenge = ticket["challenge"].as_str().and_then(|s| hex::decode(s).ok());
        let bits = ticket["bits"].as_u64().unwrap_or(0) as u32;
        let expires = ticket["expires"].as_u64().unwrap_or(0);
        let mac = ticket["mac"].as_str().and_then(|s| hex::decode(s).ok());
        let (Some(challenge), Some(mac)) = (challenge, mac) else {
            return false;
        };
        if now_ms > expires {
            return false;
        }
        let expect = hmac_sha256(&self.secret, &[&challenge, &u32be(bits), &u64be(expires)]);
        if !ct_eq(&mac, &expect) {
            return false;
        }
        let key = format!("{}:{}", hex::encode(&challenge), counter);
        if self.used.contains_key(&key) {
            return false;
        }
        if !verify_solution(&challenge, counter, bits) {
            return false;
        }
        self.used.insert(key, expires);
        if self.used.len() > 100_000 {
            self.used.retain(|_, exp| *exp >= now_ms);
        }
        true
    }
}

/// Derive a key from a passphrase for container use (scrypt N=2^15,r=8,p=1).
pub fn key_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use scrypt::{scrypt, Params};
    let params = Params::new(15, 8, 1, 32).map_err(|_| Error::Range)?;
    let mut out = [0u8; 32];
    scrypt(passphrase.as_bytes(), salt, &params, &mut out).map_err(|_| Error::Range)?;
    Ok(out)
}

#[allow(dead_code)]
fn _hkdf_present(ikm: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf_sha256(ikm, salt, b"x", &mut out);
    out
}
