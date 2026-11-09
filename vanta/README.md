# VANTA/1

**A sealed-envelope encryption and traffic-obfuscation protocol, built for a world
where the adversary is automated, post-quantum, and already recording.**

VANTA is not another block cipher. It is a complete, opinionated protocol family
that composes standard, analysed primitives into a system with properties most
deployments lack in practice: misuse resistance, key commitment, length hiding,
fixed-size records, hybrid post-quantum key establishment, forward secrecy, and a
capability layer designed to survive a rogue AI agent or a coordinated botnet.

> **Status: reference implementation, not externally audited.**
> "Military-grade" is a procurement claim, not a security property. See
> [`docs/SECURITY.md`](docs/SECURITY.md) for exactly what is and is not proven,
> and the certification path (FIPS 140-3, CNSA 2.0) required before classified
> use. Do not protect life-critical data with this yet.

---

## Why another protocol?

| Failure mode | What usually happens | What VANTA does |
|---|---|---|
| Nonce reuse | GCM/ChaCha20-Poly1305 catastrophically leak the keystream | **SIV construction**: the AEAD nonce is derived from the plaintext, so nonce reuse leaks only equality |
| Key confusion / partition oracles | A ciphertext verifies under two keys | **Key-committing tag** over an independent commitment key |
| Harvest-now-decrypt-later | Classical ECDH only | **Hybrid X25519 + ML-KEM-768**; secure if *either* survives |
| Traffic analysis | Variable record sizes fingerprint the application | **Fixed-size cells**, no cleartext magic/version/length, random padding, optional constant-rate cover |
| Exact-length leakage | Ciphertext length equals plaintext length | **Padmé** padding: O(log log M) leakage, ≤12% overhead |
| Rogue agent / stolen capability | Bearer key decrypts everything forever | **Purpose-bound capabilities**, quotas, canaries, lockouts, audit chain, Shamir custody |
| Mass handshake floods | Server burns CPU per request | **Proof-of-work admission** that escalates under load |
| Silent history rewriting | Mutable logs | **Hash-chained audit log** verifiable after the fact |

The novelty is deliberately **not** a new primitive. Inventing an unanalysed
cipher is how systems die (CWE-1240). VANTA's contribution is the *composition
and lifecycle*: an SIV+commitment envelope, a fixed-cell transport, a hybrid
handshake with two-sided freshness, and an enforcement layer for untrusted
callers. Every primitive underneath is standard and named.

## Quickstart (JavaScript reference)

```bash
cd vanta
npm install
npm test                 # 59 tests incl. tamper, replay, downgrade, policy
npm run test:browser     # browser bundle parity (handshake, cells, VSEAL, KEM)
npm run build:browser    # browser/dist + standalone browser/demo.html
node bin/vanta.js selftest
node bin/vanta.js bench

node bin/vanta.js keygen --out demo.key
printf 'hello vanta' | node bin/vanta.js seal --key demo.key --out msg.vseal --json
node bin/vanta.js open --key demo.key --in msg.vseal

node bin/vanta.js encrypt --key demo.key --in big.bin --out big.vanta --pad 1048576
node bin/vanta.js decrypt --key demo.key --in big.vanta --out big.out
```

Rust implementation:

```bash
cd vanta-rs
./cargo.sh test           # 13 tests, byte-compatible with the JS vectors
./cargo.sh run --release -- selftest
./cargo.sh run --release -- bench
```

## Architecture

```
 application message
        │
        ▼
┌───────────────────────┐   fragmentation, ids, random padding
│  VANTA/WIRE cells     │   fixed 1024 B plaintext → 1104 B on the wire
│  (no magic, no len)   │   trial-decryption over a 4-epoch window
└──────────┬────────────┘
           │ per-epoch key (ratcheted every 1024 records)
           ▼
┌───────────────────────┐   prefix = HMAC(pt, nonce) → SIV
│  VSEAL/1 envelope     │   ct = ChaCha20-Poly1305(prefix)
│  (misuse-resistant)   │   tag = HMAC(k_com, ct) → commitment
└──────────┬────────────┘
           │ keys from handshake ratchet
           ▼
┌───────────────────────┐   X25519 + ML-KEM-768, two-sided ephemeral
│  VANTA-HS/1 handshake │   confirmation both ways, transcript-bound
└──────────┬────────────┘
           │
           ▼
┌───────────────────────┐   purpose binding, quotas, canaries, lockouts,
│  VANTA/GUARD          │   circuit breaker, audit chain, Shamir 3-of-5,
│  (untrusted callers)  │   proof-of-work admission
└───────────────────────┘
```

## Transports and clients

* **TCP streaming adapter** (`@vanta/protocol/transport`): framed hybrid
  handshake, then fixed-size authenticated cells with backpressure. The server
  key must be pinned; both sides must configure the same `cellSize`. See
  [`docs/TRANSPORT.md`](docs/TRANSPORT.md).
* **Browser client** (`browser/`): an esbuild bundle of the same core code with
  WebCrypto randomness and pure-JS Noble primitives. `browser/demo.html` runs a
  complete handshake and channel self-test in the page; `npm run test:browser`
  checks bundle parity in Node. See [`docs/BROWSER.md`](docs/BROWSER.md).

Measured on one Windows x64 machine, single-threaded: the JS reference seals
1 MiB at 358 MiB/s and completes 86 handshakes/s; the Rust release build seals
at 423 MiB/s and completes 2,116 handshakes/s. See
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) for the full tables.

Full byte-level specification: [`docs/DESIGN.md`](docs/DESIGN.md).
Adversary analysis incl. rogue agents and mass coordination:
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).
Literature and rationale: [`docs/RESEARCH.md`](docs/RESEARCH.md).
Measured performance: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).
Adversarial review, findings and fixes:
[`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md).

## Byte-level guarantees

* **VSEAL overhead:** 80 bytes (16 nonce + 16 SIV prefix + 16 Poly1305 tag +
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
vanta/            JavaScript reference implementation, CLI, tests, vectors
vanta-rs/         Rust implementation (byte-compatible), CLI, tests
vanta/docs/       design, threat model, research, security, AI integration
vanta/vectors/    shared cross-language test vectors
```

## Licence

MIT.
