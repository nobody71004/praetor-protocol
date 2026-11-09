# VANTA/1 — sealed-envelope cryptosystem

VANTA/1 is a new **protocol composition** for authenticated encryption,
traffic-obfuscated framing, hybrid post-quantum key establishment and
capability enforcement. It deliberately does not invent a primitive: the
novelty is the lifecycle and composition of standard, analysed algorithms.

* **VSEAL/1** — SIV-derived nonces, ChaCha20-Poly1305, and an independent
  key-commitment tag. 80-byte envelope overhead.
* **VANTA/WIRE** — fixed 1024-byte cells with no cleartext magic, version,
  suite or length; trial decryption over a ratcheted epoch window.
* **VANTA-HS/1** — one-round-trip X25519 + ML-KEM-768 handshake, forward
  secret, confirmations in both directions.
* **VANTA/GUARD** — purpose-bound capabilities, quotas, lockouts, canaries,
  hash-chained audit, Shamir custody and one-time proof-of-work admission.
* **Adapters** — TCP streaming transport and a browser client built from the
  same core modules.

> **Status: reference implementation, not independently audited.**
> Not FIPS 140-3 validated or CNSA 2.0 compliant. Read
> [`vanta/docs/SECURITY.md`](vanta/docs/SECURITY.md) and the
> [adversarial review](vanta/docs/SECURITY-REVIEW.md) before relying on it.

## Layout

```text
vanta/            JavaScript core, CLI, TCP transport, browser bundle, tests
vanta-rs/         Rust implementation, CLI, cross-language vector tests
vanta/docs/       design, threat model, research, security review, adapters
vanta/vectors/    shared JS/Rust test vectors
```

## Verify

```bash
cd vanta
npm install
npm test                 # 59 tests
npm run test:browser     # browser bundle parity
npm run build:browser    # dist + standalone demo.html

cd ../vanta-rs
./cargo.sh test          # 14 tests (uses local toolchain if present)
./cargo.sh run --release -- selftest
```

Open `vanta/browser/demo.html` for an in-page handshake, fixed-cell and VSEAL
self-test. The Chromium run reports `handshake, channel, aead, container: true`.

## Measured

Single-threaded, Windows x64:

| Operation | JavaScript | Rust release |
|---|---:|---:|
| VSEAL seal, 1 MiB | 358 MiB/s | 423 MiB/s |
| VSEAL open, 1 MiB | 444 MiB/s | 464 MiB/s |
| X-Wing decapsulation | 218 ops/s | 10,364 ops/s |
| Full handshake | 86 ops/s | 2,116 ops/s |

Full tables and methodology: [`vanta/docs/BENCHMARKS.md`](vanta/docs/BENCHMARKS.md).

## Documentation

* [Design specification](vanta/docs/DESIGN.md)
* [Threat model](vanta/docs/THREAT-MODEL.md)
* [Security status](vanta/docs/SECURITY.md)
* [Adversarial review](vanta/docs/SECURITY-REVIEW.md)
* [TCP transport](vanta/docs/TRANSPORT.md)
* [Browser client](vanta/docs/BROWSER.md)
* [Research notes](vanta/docs/RESEARCH.md)
* [AI integration](vanta/docs/AI-INTEGRATION.md)

## License

MIT — see [LICENSE](LICENSE).
