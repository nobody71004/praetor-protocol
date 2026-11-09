# PRAETOR/1

**A post-quantum authenticated transport and enforcement protocol, built for a
world where the adversary is automated, post-quantum, and already recording.**

PRAETOR/1 introduces **PSEAL/1**, a new SIV + independent-commitment AEAD
construction, and wraps it in fixed-cell transport, hybrid post-quantum key
establishment, forward secrecy, and a capability layer designed to survive a
rogue AI agent or a coordinated botnet. PSEAL is new at the construction level;
it composes standard, analysed primitives rather than inventing a block cipher
or permutation.

> **Status: reference implementation, not externally audited.**
> "Military-grade" is a procurement claim, not a security property. See
> [`docs/SECURITY.md`](praetor/docs/SECURITY.md) for exactly what is and is not proven,
> and the certification path (FIPS 140-3, CNSA 2.0) required before classified
> use. Do not protect life-critical data with this yet.

---

## Why another protocol?

| Failure mode | What usually happens | What PRAETOR does |
|---|---|---|
| Nonce reuse | GCM/ChaCha20-Poly1305 catastrophically leak the keystream | **SIV construction**: the AEAD nonce is derived from the plaintext, so nonce reuse leaks only equality |
| Key confusion / partition oracles | A ciphertext verifies under two keys | **Key-committing tag** over an independent commitment key |
| Harvest-now-decrypt-later | Classical ECDH only | **Hybrid X25519 + ML-KEM-768**; secure if *either* survives |
| Traffic analysis | Variable record sizes fingerprint the application | **Fixed-size cells**, no cleartext magic/version/length, random padding, optional constant-rate cover |
| Exact-length leakage | Ciphertext length equals plaintext length | **Padmé** padding: O(log log M) leakage, ≤12% overhead |
| Rogue agent / stolen capability | Bearer key decrypts everything forever | **Purpose-bound capabilities**, quotas, canaries, lockouts, audit chain, Shamir custody |
| Mass handshake floods | Server burns CPU per request | **Proof-of-work admission** that escalates under load |
| Silent history rewriting | Mutable logs | **Hash-chained audit log** verifiable after the fact |

PSEAL/1 is a new **AEAD construction**, not a new block cipher or permutation.
That distinction matters: inventing an unanalysed cipher is how systems die
(CWE-1240). PSEAL's security argument rests on SIV (Rogaway–Shrimpton),
encrypt-then-MAC, and an independent commitment key — all standard, named
components. The construction itself is new and has not had years of public
cryptanalysis. Do not treat novelty as a proof of strength.

## What is actually new

| Layer | Status |
|---|---|
| **PSEAL/1** | New AEAD construction: SIV prefix + ChaCha20-Poly1305 + independent commitment tag |
| **PRAETOR/WIRE** | Fixed-cell framing with trial decryption over a bounded epoch window |
| **PRAETOR-HS/1** | Hybrid X25519 + ML-KEM-768 handshake with two-sided confirmation |
| **PRAETOR/GUARD** | Capability, quota, audit, custody and admission enforcement |

PSEAL is the new cryptographic primitive in this project. It is not a new
low-level cipher, and this repository does not claim that it is.

## Security is not a single benchmark number

PRAETOR is designed for stronger **specific** properties than WireGuard:
post-quantum key establishment, nonce-misuse resistance, ciphertext key
commitment, and fixed-cell metadata hiding. WireGuard is much more widely
reviewed, has a smaller codebase and a mature kernel data path. Those are real
security advantages too. The honest comparison is a threat-model table, not a
claim that one word makes a system invulnerable.

## Quickstart (JavaScript reference)

```bash
cd praetor
npm install
npm test                 # 59 tests incl. tamper, replay, downgrade, policy
npm run test:browser     # browser bundle parity (handshake, cells, PSEAL, KEM)
npm run build:browser    # browser/dist + standalone browser/demo.html
node bin/praetor.js selftest
node bin/praetor.js bench

node bin/praetor.js keygen --out demo.key
printf 'hello praetor' | node bin/praetor.js seal --key demo.key --out msg.pseal --json
node bin/praetor.js open --key demo.key --in msg.pseal

node bin/praetor.js encrypt --key demo.key --in big.bin --out big.praetor --pad 1048576
node bin/praetor.js decrypt --key demo.key --in big.praetor --out big.out
```

Rust implementation:

```bash
cd praetor-rs
./cargo.sh test           # 14 tests, byte-compatible with the JS vectors
./cargo.sh run --release -- selftest
./cargo.sh run --release -- bench
```

## Architecture

```
 application message
        │
        ▼
┌───────────────────────┐   fragmentation, ids, random padding
│  PRAETOR/WIRE cells     │   fixed 1024 B plaintext → 1104 B on the wire
│  (no magic, no len)   │   trial-decryption over a 4-epoch window
└──────────┬────────────┘
           │ per-epoch key (ratcheted every 1024 records)
           ▼
┌───────────────────────┐   prefix = HMAC(pt, nonce) → SIV
│  PSEAL/1 envelope     │   ct = ChaCha20-Poly1305(prefix)
│  (misuse-resistant)   │   tag = HMAC(k_com, ct) → commitment
└──────────┬────────────┘
           │ keys from handshake ratchet
           ▼
┌───────────────────────┐   X25519 + ML-KEM-768, two-sided ephemeral
│  PRAETOR-HS/1 handshake │   confirmation both ways, transcript-bound
└──────────┬────────────┘
           │
           ▼
┌───────────────────────┐   purpose binding, quotas, canaries, lockouts,
│  PRAETOR/GUARD          │   circuit breaker, audit chain, Shamir 3-of-5,
│  (untrusted callers)  │   proof-of-work admission
└───────────────────────┘
```

## Transports and clients

* **TCP streaming adapter** (`@praetor/protocol/transport`): framed hybrid
  handshake, then fixed-size authenticated cells with backpressure. The server
  key must be pinned; both sides must configure the same `cellSize`. See
  [`docs/TRANSPORT.md`](praetor/docs/TRANSPORT.md).
* **Browser client** (`browser/`): an esbuild bundle of the same core code with
  WebCrypto randomness and pure-JS Noble primitives. `browser/demo.html` runs a
  complete handshake and channel self-test in the page; `npm run test:browser`
  checks bundle parity in Node. See [`docs/BROWSER.md`](praetor/docs/BROWSER.md).

Measured on one Windows x64 machine, single-threaded: the JS reference seals
1 MiB at 358 MiB/s and completes 86 handshakes/s; the Rust release build seals
at 443 MiB/s and completes 2,177 handshakes/s. See
[`docs/BENCHMARKS.md`](praetor/docs/BENCHMARKS.md) for the full tables.

PRAETOR is **not faster than WireGuard** on the same CPU. Against userspace
`boringtun` it reaches about 0.53× the handshake rate, 0.14× the 1 KiB
roundtrip rate and 0.11× the 60 KB full-path throughput. That is the measured
cost of SIV, the commitment tag, fixed cells and ML-KEM-768. Claims that a
protocol with those properties is simultaneously faster than WireGuard would
need a different benchmark, hardware, or threat model.

![PRAETOR/1 vs WireGuard](praetor/docs/benchmarks-praetor-vs-wireguard.svg)

Against Cloudflare `boringtun` 0.7.1 (userspace WireGuard, same CPU, single
thread): PRAETOR completes **2,177 handshakes/s** vs **4,082**, **130k 1 KiB
roundtrips/s** vs **932k**, and **131.1 MiB/s** at 60 KB vs **1,193.2 MiB/s**.
This is protocol CPU cost, not a kernel-tunnel wall-clock test; PRAETOR pays for
SIV, commitment, fixed cells and a post-quantum handshake. Full methodology:
[`docs/BENCHMARKS.md`](praetor/docs/BENCHMARKS.md).

Full byte-level specification: [`docs/DESIGN.md`](praetor/docs/DESIGN.md).
Adversary analysis incl. rogue agents and mass coordination:
[`docs/THREAT-MODEL.md`](praetor/docs/THREAT-MODEL.md).
Literature and rationale: [`docs/RESEARCH.md`](praetor/docs/RESEARCH.md).
Measured performance: [`docs/BENCHMARKS.md`](praetor/docs/BENCHMARKS.md).
Adversarial review, findings and fixes:
[`docs/SECURITY-REVIEW.md`](praetor/docs/SECURITY-REVIEW.md).

## Byte-level guarantees

* **PSEAL overhead:** 80 bytes (16 nonce + 16 SIV prefix + 16 Poly1305 tag +
  32 commitment tag). Deterministic mode: 64 bytes.
* **Cell overhead:** 80 bytes; 1024-byte cell → 1104 bytes on the wire.
* **No cleartext structure:** no magic, version, suite id, message length or
  record count is visible. A wrong key sees random bytes.
* **Fail closed:** tag → decrypt → prefix re-derivation; no unauthenticated
  plaintext is ever released.
* **Replay/reorder/truncation/splice:** detected by message ids, fragment
  indices, per-chunk AAD and a final-chunk flag.

## Non-goals

* Not a replacement for TLS on the public web; no PKI, OCSP, or ALPN.
* Not formally verified; the security argument is by reduction to named
  primitives, not machine-checked.
* Not FIPS 140-3 validated, not CNSA 2.0 compliant (that requires ML-KEM-1024,
  AES-256/SHA-384 and a validated module boundary).
* The JS implementation is not constant-time (JIT). Use the Rust build where
  local side channels are in scope.

## Layout

```
praetor/            JavaScript reference implementation, CLI, tests, vectors
praetor-rs/         Rust implementation (byte-compatible), CLI, tests
praetor/docs/       design, threat model, research, security, AI integration
praetor/vectors/    shared cross-language test vectors
```

## Licence

MIT.
