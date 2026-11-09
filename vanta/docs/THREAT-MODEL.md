# VANTA/1 — Threat Model

## 1. Assets

* plaintext content and its metadata (length, timing, direction, equality);
* long-term identity keys and per-session keys;
* capability policy (who may decrypt what, for which purpose);
* audit history and its integrity;
* availability of the service under flood.

## 2. Adversaries

### A1. Passive network observer
Records all traffic now, decrypts later if a key or algorithm falls. Capabilities:
full packet capture, timing, sizes, direction; no key material.

**Mitigations:** hybrid PQ KEM; fixed-size cells; Padmé; optional constant-rate
cover; no cleartext headers; forward-secret ratchet.

### A2. Active network attacker
Injects, drops, reorders, replays, truncates, partitions, and attempts downgrade.

**Mitigations:** authenticated transcript; explicit confirmations; no algorithm
negotiation; per-cell AAD; replay window; final-chunk flag; fail-closed errors.

### A3. Malicious server operator
Holds server keys, can read memory, may try to decrypt past sessions.

**Mitigations:** forward secrecy via the client's ephemeral KEM contribution;
split custody for high-value keys; audit chain; no plaintext key export API.

### A4. Rogue AI agent (the new threat)
An LLM-driven process with tool access, possibly prompt-injected or
goal-misgeneralised. It can call APIs at machine speed, chain tools, retry
aggressively, and exfiltrate anything it can read. It is **not** assumed to be
malicious by intent — only untrusted by capability.

Attack paths and controls:

| Attack | Control |
|---|---|
| Read the key file and decrypt everything | Keys live behind `Keyring`; agents get capability ids, never key bytes |
| Use a capability for an unintended dataset | Purpose binding in the AAD; policy allowlist |
| Loop decrypt attempts to build an oracle | Per-key auth-failure lockout + global circuit breaker |
| Drain budget / cause denial of service | Token bucket, per-op and total byte budgets, cryptoperiod |
| Quietly rewrite what it did | Hash-chained audit log; ship the head off-box |
| Use a stolen but valid capability | Canary capabilities alert on use; quotas bound damage |
| Single agent reconstructs a high-value key | Shamir k-of-n custody across trust domains |
| Prompt injection asks it to print keys | No key-returning API; CLI refuses unless explicitly forced; manifest marks dangerous ops |
| Model hallucinates a dangerous action | Deny-by-default policy; irreversible ops require human approval outside the model |

**Residual risk:** an agent with OS-level access to process memory or the key
file bypasses the guard. The guard is an authorization boundary, not a
cryptographic one. Isolate key material in another process/HSM.

### A5. Mass coordination / botnet
Thousands of nodes perform handshakes, probe keys, or attempt decryptions in
parallel. Goals: resource exhaustion, oracle amplification, key discovery.

**Mitigations:** proof-of-work admission that escalates with request pressure;
per-source and global quotas; circuit breaker that sheds load early; 2368-byte
handshake with no server state before ticket validation; constant-time failure
paths; per-key lockouts. The attacker's cost grows super-linearly with pressure,
while a single honest client pays milliseconds.

**Residual risk:** a distributed attacker with more CPU than the defender can
still degrade availability. PoW raises cost; it does not create capacity.

### A6. Local side-channel attacker
Shares a machine or observes caches, branches, timing.

**Mitigations (Rust):** constant-time tag comparison, no secret-dependent
branches in tag/prefix checks, zeroisation on drop.
**Known weakness (JS):** V8 is not a constant-time execution environment. Do not
run the JS build where local side channels are in scope.

### A7. Supply chain attacker
Compromises a dependency, build, or distribution channel.

**Mitigations:** four runtime dependencies, all audited and pinned; no native
code in the JS build; shared cross-language vectors; Rust crate with a small
dependency set; reproducible test command. This does not eliminate the risk —
verify the lockfile and build artifacts yourself.

### A8. Cryptanalytic advance
A break in ChaCha20-Poly1305, SHA-256, X25519, or ML-KEM-768.

**Mitigations:** hybrid KEM; 256-bit symmetric keys; versioned suites. There is
no agility *negotiation* (which would enable downgrade); migration is an
explicit deployment decision. A break in SHA-256 would affect HMAC-SHA-256; the
design's dependency on it is deliberate and documented.

## 3. What VANTA does not protect against

* A compromised endpoint that reads plaintext before encryption.
* A user or agent that legitimately holds a capability and misuses it within its
  policy (canaries and audit reduce, not eliminate, this).
* Coercion of key holders; split custody raises the bar, not to infinity.
* Global traffic analysis that correlates flows by timing at the network edge,
  unless constant-rate cover is enabled end to end.
* Malicious modifications to the implementation you actually run.
* Quantum cryptanalysis of X25519 *combined with* a break of ML-KEM-768.
* FIPS/CNSA certification claims — see SECURITY.md.

## 4. Security objectives

| Objective | Mechanism | Residual |
|---|---|---|
| Confidentiality | VSEAL (SIV + ChaCha20-Poly1305) | 2^-128 per forgery under standard assumptions |
| Integrity | independent commitment tag + AEAD | same |
| Nonce-misuse resistance | SIV prefix | equality leak only in deterministic mode |
| Key commitment | `k_com` tag over ciphertext | negligible |
| Forward secrecy | ephemeral client KEM + ratchet | static server key compromise after session is survivable |
| Post-quantum | hybrid X25519 + ML-KEM-768 | either component may fall |
| Length privacy | Padmé + fixed cells | O(log log M) bits; cell count still visible without cover |
| Authorization | purpose-bound capabilities | policy bugs remain possible |
| Non-repudiation of actions | audit chain | head truncation needs external anchoring |
| Availability | PoW admission + quotas + breaker | capacity-bound |

## 5. Abuse cases explicitly considered

1. **Agent exfiltrates a customer database using a valid "support" capability.**
   Purpose binding fails the AAD; if the capability was minted for support, the
   policy still caps bytes and the canary may catch it.
2. **Botnet opens 10^6 handshakes.** Admission difficulty rises; pre-ticket
   server work is a MAC check, not a KEM decapsulation.
3. **Operator tries to read a past session after seizing the server.** `ss2`
   required the client's ephemeral secret, already destroyed.
4. **Attacker replays a valid ciphertext to a logging service.** Replay window
   rejects the duplicate `(msgId, fragIndex)`.
5. **Attacker swaps a chunk between two files.** Chunk AAD binds index and final
   flag; authentication fails.
6. **Two keys decrypt the same ciphertext (partition oracle).** Commitment tag
   makes this infeasible.
7. **Agent is asked to "print the key for debugging".** No API returns raw keys;
   the manifest marks `keygen --stdout` and `combine --stdout` as dangerous.
8. **Coerced insider with one share.** k-of-n custody prevents reconstruction.
