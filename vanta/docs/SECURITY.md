# Security Status

## Summary

VANTA/1 is a **reference implementation of a new protocol composition**. It has
not been independently audited, formally verified, or certified. A
maintainer-run adversarial review with fixes is in
[`SECURITY-REVIEW.md`](SECURITY-REVIEW.md); it is not a substitute for an
independent audit. It should not
protect life-critical, classified, or high-value production data until the work
in §6 is done.

What it does have: a byte-level specification, 59 JavaScript and 14 Rust
automated tests (including shared cross-language vectors) covering
tamper/replay/truncation/downgrade/policy failures, shared cross-language test
vectors, randomized property tests, and an explicit threat model.

## What is proven, and what is only argued

| Property | Basis |
|---|---|
| Confidentiality/integrity of an envelope | Reduction to ChaCha20-Poly1305 (RFC 8439) + HMAC-SHA-256 + HKDF |
| Nonce-misuse resistance | SIV construction (Rogaway–Shrimpton; RFC 5297) |
| Encrypt-then-MAC integrity | Bellare–Namprempre (ASIACRYPT 2000) |
| Hybrid PQ security | X-Wing argument (ePrint 2024/039): secure if either X25519 or ML-KEM-768 is secure |
| Commitment | HMAC under an independent derived key; forgery requires breaking HMAC-SHA-256 |
| Forward secrecy | Ephemeral client KEM secret destroyed after the handshake; ratchet erases old keys |
| Length leakage bound | Padmé analysis (PETS 2019) |
| Replay/truncation resistance | Protocol invariants, tested |

These are **arguments by composition**, not machine-checked proofs. No formal
verification (ProVerif/Tamarin/CryptoVerif) has been run on the handshake.

## Known limitations

1. **Novel composition.** SIV+commitment+fixed cells is new as a whole. The
   primitives are standard; the composition has not been cryptanalysed by third
   parties.
2. **JavaScript is not constant-time.** V8 may optimise secret-dependent
   branches. Use the Rust build where local attackers are in scope.
3. **Memory zeroisation is best-effort.** GC languages may copy buffers; OS
   swapping is outside our control. Use `mlock`/HSM integration in production.
4. **The guard is an authorization layer, not a cryptographic boundary.** An
   attacker who can read the key process's memory bypasses it.
5. **No post-compromise security (healing).** The symmetric ratchet is one-way
   only; a leaked epoch key compromises that epoch, not past/future epochs, but
   the session does not heal from a full state compromise. A DH ratchet is future
   work.
6. **Traffic analysis is only partially addressed.** Fixed cells hide lengths;
   without constant-rate cover, counts and timings remain.
7. **Deterministic mode leaks equality.** That is the SIV trade-off; document it
   wherever the option is exposed.
8. **No in-band agility.** Suite changes require a deployment/version change, by
   design. This is safer against downgrade but slower to migrate.
9. **Passphrase mode relies on scrypt N=2^15.** Weak passphrases remain weak;
   use a high-entropy key or Argon2id with tuned parameters where available.

## "Military-grade" — an honest reading

The phrase has no formal definition. The properties a defence buyer actually
means are usually:

- vetted algorithms (yes: ChaCha20, SHA-256, X25519, ML-KEM-768, scrypt);
- misuse resistance (yes, by construction);
- post-quantum migration (hybrid, yes; CNSA 2.0 profile, not yet);
- key lifecycle and split custody (yes, in the guard layer);
- side-channel resistance (Rust yes/JS no);
- validated module boundary (no);
- independent cryptanalysis (no);
- supply-chain assurance (small dependency set, not attested);
- certified configuration (no).

The first five are engineering properties this project can demonstrate. The last
four are process and certification properties that no amount of code can
self-certify.

## Reporting

Do not open a public issue for a suspected vulnerability. Send a minimal
reproducer and affected version to the maintainer privately, then allow 90 days
before disclosure. Include whether the issue affects the JS build, the Rust
build, or both.

## Hardening checklist before production

- [ ] Independent audit of VSEAL and VANTA-HS/1 (composition, not just primitives)
- [ ] Formal verification of the handshake (secrecy, agreement, key confirmation)
- [ ] Constant-time review of the Rust build; `cargo audit`, `cargo deny`
- [ ] Fuzz targets for envelope parsing, cell parsing, container parsing
- [ ] HSM-backed key custody; guard runs in a separate process
- [ ] External anchoring of the audit-log head
- [ ] TLS-style traffic shaping evaluation against a real classifier
- [ ] Key-rotation runbook and cryptoperiod policy
- [ ] FIPS 140-3 validated module if required by procurement
- [ ] CNSA 2.0 suite (ML-KEM-1024 + AES-256-GCM + SHA-384) if required
- [ ] Reproducible builds and signed releases
