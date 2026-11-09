# PRAETOR/1 — Protocol Specification

Normative language: **MUST**, **MUST NOT**, **SHOULD**. All integers are
big-endian. `||` is concatenation. `H` is SHA-256. `H3` is SHA3-256.
`HMAC(k, m)` is HMAC-SHA-256. `HKDF(ikm, salt, info, L)` is HKDF-SHA-256
(RFC 5869). `AEAD(k, n, pt, ad)` is ChaCha20-Poly1305 (RFC 8439, 96-bit nonce,
128-bit tag) returning `ct || tag`.

## 1. Keys and domains

A PRAETOR master key is exactly 32 bytes. Every use of a key is domain-separated
by an ASCII label; labels are part of the wire contract and MUST NOT change
without a version bump.

```
HKDF-SHA256(ikm = K, salt = "PRAETOR/1", info = "pseal", L = 96)
    -> k_siv (32) || k_enc (32) || k_com (32)
```

## 2. PSEAL/1 — sealed envelope

### 2.1 Seal

Inputs: `pt`, `aad` (may be empty), mode ∈ {probabilistic, deterministic},
optional 16-byte caller nonce.

```
nonce = 16 random bytes                      (probabilistic)
nonce = ε                                    (deterministic)

prefix = HMAC(k_siv,
              "PSEAL/1/siv" || nonce ||
              u64(|aad|) || aad ||
              u64(|pt|)  || pt)[0..16]

ct  = AEAD(k_enc, prefix[0..12], pt, "PSEAL/1/aead" || aad)   // ct||tag16

tag = HMAC(k_com,
           "PSEAL/1/tag" || nonce || prefix || ct ||
           H("PSEAL/1/aad" || aad))                          // 32 bytes

envelope = nonce || prefix || ct || tag
```

Overhead is constant: **80 bytes** probabilistic, **64 bytes** deterministic.
The 16-byte AEAD tag is inside `ct`, hence the extra 16 relative to a naive
count.

### 2.2 Open

1. If `len < 80` (or `< 64` deterministic) → `TRUNCATED`.
2. Split `nonce`, `prefix`, `ct`, `tag`.
3. Recompute `tag'` and compare in constant time. If unequal → `AUTH_FAILED`.
   This check happens **before** any decryption and is the key-commitment check.
4. `pt = AEAD-Open(k_enc, prefix[0..12], ct, ad')`. Any failure → `AUTH_FAILED`.
5. Recompute `prefix'` from `pt`, `aad`, `nonce`; compare with `prefix`. If
   unequal → `AUTH_FAILED`.

Invariant: a successful `Open` implies the exact tuple `(K, nonce, aad, pt)`
that produced the envelope, up to a 2^-128 forgery probability.

### 2.3 Why each check exists

| Check | Prevents |
|---|---|
| commitment `tag` before decrypt | key-partition oracles, invisible salamanders, cross-key confusion |
| independent `k_com` | tag collisions across keys |
| `prefix` re-derivation | substituting a valid AEAD body from another message |
| SIV prefix as AEAD nonce | catastrophic nonce-reuse keystream reuse |
| constant-time compares | timing oracles on tags |

The only deliberate leak is in deterministic mode: equal `(pt, aad)` produce
equal envelopes. Probabilistic mode does not leak equality.

### 2.4 Limits

* Maximum message: 2^32 − 1 bytes per envelope (practical limit; the SIV MAC is
  computed over the whole message, so streaming requires the container layer).
* Per-key envelope count before rotation: **2^32** (SIV prefix collision bound is
  ~2^64; 96-bit AEAD nonce birthday bound is ~2^48).
* Caller nonce reuse is safe. Nonce *omission* (deterministic mode) leaks
  equality by design.

### 2.5 PMARINE/1 — experimental PSEAL/2 profile

PMARINE is a Rust-only, opt-in envelope profile. It is **not** the default and
has not been audited. It keeps the SIV construction but uses AEGIS-256
(RFC 10032) with a 256-bit tag instead of ChaCha20-Poly1305 plus a separate
commitment tag.

```
HKDF-SHA256(K, salt = "PRAETOR/1", info = "pmarine", L = 64)
    -> k_siv (32) || k_enc (32)

nonce = 16 random bytes                      (probabilistic)
nonce = ε                                    (deterministic)

siv = HMAC(k_siv,
           "PMARINE/1/siv" || nonce ||
           u64(|aad|) || aad ||
           u64(|pt|)  || pt)                 // 32 bytes

ct || tag = AEGIS-256(k_enc, nonce = siv, pt,
                      "PMARINE/1/aead" || aad) // 32-byte tag

envelope = nonce || siv || ct || tag
```

Overhead is **80 bytes** probabilistic and **64 bytes** deterministic. The SIV
is the AEGIS nonce; distinct plaintexts under one outer nonce therefore get
distinct AEGIS nonces. Open verifies the AEGIS tag first, then recomputes the
SIV from the recovered plaintext and compares in constant time. The SIV check is
the independent commitment and does not rely on AEGIS's built-in commitment,
which is not full when the adversary controls the associated data
(IACR ePrint 2023/1495; RFC 10032 §9.1.2).

Limits: AEGIS-256 caps plaintext and associated data at 2^61 − 1 bytes; rotate
well before 2^64 envelopes. Deterministic mode leaks equality by design.
PMARINE is not part of the JavaScript reference.

## 3. PRAETOR/WIRE — fixed cells

### 3.1 Cell plaintext

Exactly `cellSize` bytes (`17 ≤ cellSize ≤ 65519`, default 1024):

```
offset  size  field
0       1     type      0=DATA 1=PAD 2=CTRL 3=FIN
1       1     flags     reserved, MUST be 0
2       2     fragIndex
4       2     fragCount  1..65535
6       8     msgId      random start, monotonic per sender
14      2     payloadLen
16      n     payload
16+n    ...   random padding to exactly cellSize
```

Padding bytes are uniformly random, not zero: a compressed or encrypted-looking
cell must not reveal where the payload ends.

### 3.2 Sealing

```
aad  = "PRAETOR/1/cell" || u16(cellSize)
wire = PSEAL.Seal(epochKey, cellPlaintext, aad)     // cellSize + 80 bytes
```

There is no cleartext header. The receiver identifies a valid cell by
successful authentication.

### 3.3 Epochs and ratchet

```
key(e)     = HKDF(chain[e], "PRAETOR/1/record", "PRAETOR/1/epoch" || u32(e), 32)
chain[e+1] = HMAC(chain[e], "PRAETOR/1/ratchet" || u32(e))
```

Record `i` uses epoch `floor(i / 1024)`. The receiver tries epochs
`max(0, e-1) .. e+2` where `e = floor(opened / 1024)`, accepting the first that
authenticates, then commits. Old chain states and keys are erased when they
fall out of the window. This bounds reordering and tolerates up to two lost
epochs, at the cost of up to four HMAC+AEAD attempts on the failure path
(normally one).

### 3.4 Replay and reassembly

* `(msgId, fragIndex)` is accepted at most once within a 4096-message window.
* Fragments of one message MUST share `fragCount`; duplicates are dropped.
* A message completes when all `fragCount` fragments arrive; total size is
  bounded by policy (default 64 MiB).
* `PAD` cells are authenticated, counted for replay, and discarded.

### 3.5 Length hiding on the wire

All cells are equal size, so a passive observer learns only *how many* cells
were sent and when. To hide that too, enable cover traffic: send `PAD` cells at
a constant rate with bounded jitter (`coverSchedule`). Random padding alone is
known to be insufficient against modern classifiers (see RESEARCH.md); constant
rate is the strong option.

## 4. PRAETOR-HS/1 — handshake

Precondition: the client possesses an authentic copy of the server's hybrid
public key (pinned, or delivered by an authenticated channel).

### 4.1 Messages

```
C -> S : ct1 (1120) || ephC.pk (1216) || nonceC (32)          = 2368
S -> C : ct2 (1120) || nonceS (32) || confirmS (32)           = 1184
C -> S : confirmC (32)
```

Client:
1. `ephC = KEM.KeyGen()`
2. `(ss1, ct1) = KEM.Encap(serverPk)`
3. send `ct1 || ephC.pk || nonceC`

Server:
1. `ss1 = KEM.Decap(ct1, serverSk)` — authenticates the client's view of the server
2. `(ss2, ct2) = KEM.Encap(ephC.pk)`
3. `transcript = C1 || ct2 || nonceS`
4. derive keys (4.2), send `ct2 || nonceS || confirmS`

Client:
1. `ss2 = KEM.Decap(ct2, ephC.sk)`; verify `confirmS`; send `confirmC`.
2. Destroy `ephC.sk` and `ss1`, `ss2`.

Server: verify `confirmC` before releasing the session.

### 4.2 Key schedule

```
transcriptHash = H(transcript)
ss = H3("PRAETOR-HS/1" || ss1 || ss2 || ct1 || ct2 || ephC.pk || transcriptHash)
keys = HKDF(ss, salt = H(nonceC || nonceS), info = "PRAETOR/1/session", 96)
     = c2s (32) || s2c (32) || confirmKey (32)
sessionId = H("PRAETOR/1/session-id" || ss || transcriptHash)

confirmS = HMAC(confirmKey, "PRAETOR/1/server-confirm" || transcriptHash)
confirmC = HMAC(confirmKey, "PRAETOR/1/client-confirm" || transcriptHash)
```

### 4.3 Properties

* **Hybrid:** breaking X25519 *or* ML-KEM-768 alone does not recover `ss`.
* **Implicit authentication:** only the holder of `serverSk` can produce `ss1`.
* **Forward secrecy:** `ss2` depends on `ephC.sk`, destroyed after the
  handshake. A later compromise of `serverSk` cannot recover `ss2`.
* **Downgrade resistance:** no algorithm negotiation; the transcript hash binds
  every byte, including the KEM ciphertexts.
* **Explicit confirmation:** both directions prove key possession before
  payloads are accepted.

### 4.4 KEM construction (PRAETOR-KEM/1)

X-Wing structure with a PRAETOR domain label:

```
pk = ML-KEM-768.pk (1184) || X25519.pk (32)                  = 1216
sk = ML-KEM-768.sk (2400) || X25519.sk (32)                  = 2432
ct = ML-KEM-768.ct (1088) || X25519.ephemeral pk (32)        = 1120

Encap(pk):
  (ssM, ctM) = ML-KEM.Encap(pkM)
  esk        = random 32
  ctX        = X25519(esk, pkX)
  ssX        = X25519(esk, pkX)
  ss         = H3("PRAETOR-KEM/1 X-Wing" || ssM || ssX || ctX || pkX)

Decap(ct, sk):
  ssX = X25519(skX, ctX)
  ssM = ML-KEM.Decap(ctM, skM)
  ss  = H3("PRAETOR-KEM/1 X-Wing" || ssM || ssX || ctX || pkX)
```

The label is protocol-specific on purpose: PRAETOR shared secrets must not be
interchangeable with another X-Wing deployment. This is the X-Wing combiner
structure, not a claim of wire interoperability with the CFRG draft.

## 5. PRAETOR/CONTAINER — files

```
salt (16) || u32(headerLen) || headerEnvelope ||
(u32(chunkLen) || chunkEnvelope)*
```

Header plaintext:

```
0   1   version = 1
1   1   suite = 1 (PSEAL/1)
2   2   reserved = 0
4   4   chunkSize
8   8   totalSize (padded, may exceed the real size)
16  8   realSize (authenticated plaintext length, <= totalSize)
24  4   flags
28  2   nameLen
30  n   name (UTF-8, optional)
```

Each chunk is `PSEAL.Seal(chunk, "PRAETOR/1/file/chunk" || u64(index) || final)`.
The final chunk carries `final = 1`; a container without a valid final chunk is
truncated. Chunk indices MUST be contiguous and the produced byte count MUST
equal `totalSize`. After the final chunk is authenticated, the receiver emits
exactly `realSize` bytes and discards the padding; `realSize > totalSize` is
rejected before any chunk is processed.

Passphrase mode: `K = scrypt(passphrase, salt, N=2^15, r=8, p=1, dkLen=32)`.
The salt is unique per file, so identical passphrases produce unrelated keys.

Padding: `totalSize = Padmé(|plaintext|, M)`, with the remaining bytes filled
with random data before chunking. Padmé's overhead bound is ~12% and its
leakage is O(log log M) bits (see RESEARCH.md).

## 6. PRAETOR/GUARD — capability enforcement

Raw keys are never handed to untrusted callers. A `Keyring` maps an opaque
capability id to key material plus a policy, and binds every envelope to an
intent:

```
useAad = "PRAETOR/1/intent" || u16(|purpose|) || purpose || aad
```

A ciphertext sealed for `read:config` therefore cannot be opened under
`read:customers` even by a caller that holds the capability id: the AAD differs
and authentication fails.

Policy fields: `purposes`, `maxOpsPerMinute`, `burst`, `maxBytesPerOp`,
`maxTotalBytes`, `maxKeyAgeMs`, `maxAuthFailures`, `lockoutMs`, `canary`.

Enforcement order: circuit breaker → revocation → lockout → cryptoperiod →
purpose → per-op size → total budget → rate limit. Denials are audited.

### 6.1 Audit chain

```
entry = {seq, ts, kind, ...fields}
mac   = HMAC(auditKey, prevMac || canonicalJSON(entry))
```

Entries are append-only and verified by recomputation. Truncation of the head is
detectable only if the expected head is stored elsewhere; ship the head to an
external monitor.

### 6.2 Canaries

A canary capability is a decoy: `seal` emits well-formed ciphertext from decoy
material, `open` returns deterministic fake plaintext of the same length, and
both raise a `critical` alert. This converts silent exfiltration into a
detectable event. Canaries MUST be unique and never used for real data.

### 6.3 Split custody

`shamirSplit(secret, n, k)` over GF(2^8) produces `n` shares; any `k` reconstruct.
Each share is `[x || y]`. Duplicate indices are rejected. Use 3-of-5 for
high-value keys and store shares in separate trust domains (HSM, offline safe,
different operators). No single rogue agent can reconstruct the key.

### 6.4 Admission control

`AdmissionGate` issues a ticket binding `(challenge, difficulty, expiry)` with a
server MAC. Difficulty rises from `baseBits` to `maxBits` as requests per second
exceed capacity. The client must find a counter whose
`H(challenge || u64(counter))` has that many leading zero bits. A flood therefore
costs the attacker CPU that grows with pressure, while one honest client pays
milliseconds.

## 7. Error codes

| Code | Meaning | Required handling |
|---|---|---|
| `AUTH_FAILED` | tag/prefix mismatch, wrong key, wrong AAD | do not distinguish causes; count toward lockout |
| `MALFORMED` | structurally invalid input | reject, no retry with the same bytes |
| `TRUNCATED` | input ended early | reject |
| `REPLAY` | duplicate `(msgId, fragIndex)` | drop silently |
| `POLICY` | quota, purpose, lockout, breaker | surface to operator, audit |
| `KEY` | unknown/revoked capability, bad key length | configuration error |
| `RANGE` | caller argument out of bounds | programming error |

## 8. Versioning

Any change to a label, field order, size, or check requires a new version byte
inside the envelope (currently only in the container header; the wire relies on
the key schedule and AAD for domain separation). Implementations MUST reject
unknown container versions. There is no in-band negotiation, by design.

## 9. Invariants (tested)

1. `Open(Seal(K, pt, aad), K, aad) = pt` for all sizes 0..1 MiB.
2. Flipping any envelope byte yields `AUTH_FAILED`.
3. `Open` under a different key yields `AUTH_FAILED`.
4. Reusing a caller nonce with different plaintexts is safe.
5. Cell wire length is independent of payload.
6. Any replayed cell is rejected.
7. Any handshake byte flip is detected before payloads flow.
8. A container with a missing or reordered chunk is rejected.
9. Purpose-mismatched decryption fails even with the correct key.
10. Audit chain recomputation detects edited entries.
