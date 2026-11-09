# VANTA/1 — Research Notes

This document records what was read, what was rejected, and why the final
composition looks the way it does. Every claim below is traceable to a published
source or a standard.

## 1. Do not invent a primitive

CWE-1240 ("Use of a Cryptographic Primitive with a Risky Implementation") states
the industry position plainly: custom or private algorithms "will likely be
exposed to attacks that are well-understood by cryptographers", and even novel
modes of operation should be avoided. The empirical study *You Really Shouldn't
Roll Your Own Crypto* (arXiv:2107.04940) catalogues how cryptographic libraries
fail at the protocol and implementation layers, not just in the primitive.

**Decision:** VANTA invents no block cipher, permutation, or hash. It invents a
*composition, framing and lifecycle* and proves each step by reduction to a
named primitive. The novel parts are the SIV+commitment envelope layout, the
fixed-cell transport with trial decryption, the two-sided hybrid handshake, and
the capability guard.

## 2. AEAD selection

Measured throughput on x86 with AES-NI typically puts AES-GCM at 2.4–3.3 GiB/s
and ChaCha20-Poly1305 at 1.6–1.9 GiB/s (ring/RustCrypto benchmarks;
libsodium docs). AEGIS-128L/256 is faster still on AES-NI/VAES hardware
(libsodium ≥ 1.0.19, standard track). On hardware without AES acceleration,
ChaCha20 is several times faster than AES-GCM.

**Decision:** ChaCha20-Poly1305 (RFC 8439) as the inner AEAD. Rationale: uniform
performance across x86/ARM/low-end, no cache-timing dependence on table lookups,
and a simple, widely implemented standard. AES-GCM would be faster on
AES-NI-only fleets; that is a suite-2 option, not a correctness issue. AEGIS
remains a performance upgrade path once its implementations are as ubiquitous.

AES-GCM-SIV (RFC 8452) was considered for nonce-misuse resistance. It is
excellent but AES-bound; VANTA needs to run well on machines without AES
acceleration. Building SIV from HMAC-SHA-256 + ChaCha20-Poly1305 gives the same
misuse-resistance property with a portable primitive set.

## 3. SIV and commitment

* Rogaway & Shrimpton, *Deterministic Authenticated-Encryption*, EUROCRYPT 2006,
  and RFC 5297 define SIV: derive the IV from the plaintext with a PRF, then
  encrypt. Nonce misuse then leaks only equality.
* Bellare & Namprempre, *Authenticated Encryption: Relations among notions and
  analysis of the generic composition paradigm*, ASIACRYPT 2000: Encrypt-then-MAC
  with independent keys is INT-CTXT secure.
* Key commitment / invisible salamanders: a ciphertext that decrypts under two
  keys breaks partition oracles and some escrow designs. A tag under an
  independent `k_com` derived from the same master key makes commitment
  negligible to forge.

**Decision:** VSEAL = SIV prefix + ChaCha20-Poly1305 + independent commitment tag
+ prefix re-derivation. This is a composition of three proven ideas, not a new
one, and its failure modes are the union of theirs.

## 4. Post-quantum key establishment

FIPS 203 standardised ML-KEM in August 2024. NIST SP 800-227 recommends
ML-KEM-768 as the default parameter set (category 3, ample margin).
X-Wing (ePrint 2024/039; draft-connolly-cfrg-xwing-kem) combines X25519 with
ML-KEM-768 and is secure if either component is secure, with a fixed 32-byte
shared secret and no ciphertext hashing. RFC 10024 defines X25519MLKEM768 for
TLS 1.3, confirming the hybrid direction.

**Decision:** X-Wing structure with a VANTA-specific hash label. Two KEM
operations per handshake (client→server static, server→client ephemeral) give
implicit authentication *and* forward secrecy against later server-key
compromise. ML-KEM-1024 is the CNSA 2.0 profile and a planned suite, not the
default: it costs ~30% more key/ciphertext bytes for a higher margin.

Performance: ML-KEM-768 keygen ≈ 11.7 µs, encaps ≈ 19.1 µs, decaps ≈ similar on
a modern server (PQC Arena, 2026). Two X-Wing operations are therefore well under
0.1 ms of CPU per handshake — negligible next to a network round trip.

## 5. Length hiding

* *Reducing Metadata Leakage from Encrypted Files and Communication with PURBs*
  (PETS 2019) introduces Padmé: represent the padded length as a binary float
  whose mantissa is no longer than its exponent. Leakage O(log log M), overhead
  ≤12%, mean ~3% on real datasets.
* *Peek-a-Boo, I Still See You* (IEEE S&P 2012) shows padding alone fails against
  strong classifiers; fixed-size, fixed-rate shaping (BuFLO) is materially
  stronger but expensive.
* Encrypted-DNS traffic-analysis work (NDSS 2020) shows standardised padding
  (EDNS0-128/468) does not stop modern classifiers.
* *Shaperd* (FOCI 2025) demonstrates real-time shaping for fully encrypted
  protocols with ~4% overhead in preliminary tests.

**Decision:** three layers, honestly labelled. Padmé for files and messages.
Fixed-size cells for streams. Optional constant-rate cover traffic for
adversaries that can time packets. No claim that padding alone defeats a
website-fingerprinting adversary.

## 6. Replay, reordering and truncation

Standard authenticated-framing practice: unique message ids, fragment indices,
a sliding replay window, and a final-chunk marker. Truncation attacks are the
reason the container must authenticate both `totalSize` and the real plaintext
length, and require a final chunk.

## 7. Agent and insider threats

There is little peer-reviewed literature specific to LLM-agent key misuse; the
controls here come from established practice:

* **Capability security** (object-capability model): hand out unforgeable
  references with attached rights, not bearer keys.
* **Split custody / dual control:** NIST SP 800-57 and common financial-control
  practice; Shamir 3-of-5 is the standard mechanism.
* **Canaries / honeytokens:** deception detects misuse that prevention misses.
* **Tamper-evident logs:** hash chains (as in Certificate Transparency) make
  silent edits detectable; external anchoring closes the truncation gap.
* **Proof-of-work admission:** hashcash (Back, 2002) applied to handshakes;
  difficulty adaptation follows the same logic as adaptive PoW in anti-spam.

## 8. Rejected designs

| Option | Why rejected |
|---|---|
| New ARX/SPN block cipher | No cryptanalysis, CWE-1240; unacceptable |
| Custom sponge mode | Same; would need years of analysis |
| AES-GCM only | Terrible nonce-reuse failure; slow without AES-NI |
| GCM-SIV only | AES-bound; less portable |
| Rely on TLS 1.3 alone | No fixed-cell obfuscation, no capability layer, no misuse resistance, no file format |
| Steganography / "unbreakable" encoding | Not a security property; adds detectability risk |
| Homomorphic / MPC for this use case | Orders of magnitude slower; wrong tool |
| Rolling own ML-KEM | FIPS 203 implementations are subtle; use audited code |
| In-band algorithm negotiation | Downgrade surface; version is fixed by deployment |

## 9. Certification path (not currently claimed)

For classified or regulated use, the following would be required in addition to
this code:

1. **FIPS 140-3** validation of the module boundary and algorithms (requires a
   validated cryptographic module such as OpenSSL's FIPS provider or AWS-LC;
   pure JS cannot satisfy this).
2. **CNSA 2.0** profile: ML-KEM-1024, AES-256-GCM, SHA-384/512; a suite-2
   implementation with those primitives.
3. Independent third-party cryptanalysis of the *composition* (not just the
   primitives), including the guard layer.
4. Side-channel evaluation (power, timing, cache) on the target hardware.
5. Key-management audit: HSM integration, split-custody procedures, rotation.
6. Operational security: TEMPEST, supply-chain attestation, reproducible builds.

Until then, the accurate description is: **a carefully composed, tested,
reference-grade protocol with explicit threat modelling** — not "military-grade".

## 10. References

- CWE-1240 — https://cwe.mitre.org/data/definitions/1240.html
- *You Really Shouldn't Roll Your Own Crypto* — https://arxiv.org/pdf/2107.04940
- RFC 8439 — https://www.rfc-editor.org/rfc/rfc8439
- RFC 5297 (SIV) — https://www.rfc-editor.org/rfc/rfc5297
- RFC 8452 (AES-GCM-SIV) — https://www.rfc-editor.org/rfc/rfc8452
- RFC 5869 (HKDF) — https://www.rfc-editor.org/rfc/rfc5869
- FIPS 203 (ML-KEM) — https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
- X-Wing — https://eprint.iacr.org/2024/039
- draft-connolly-cfrg-xwing-kem — https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
- RFC 10024 (X25519MLKEM768 for TLS) — https://www.rfc-editor.org/rfc/rfc10024.pdf
- PURBs / Padmé — https://petsymposium.org/popets/2019/popets-2019-0056.pdf
- *Peek-a-Boo, I Still See You* — https://www.computer.org/csdl/proceedings-article/sp/2012/06234422/12OmNBOUxsT
- Encrypted DNS traffic analysis — https://www.ndss-symposium.org/wp-content/uploads/2020/02/24301-paper.pdf
- Shaperd — https://www.petsymposium.org/foci/2025/foci-2025-0010.pdf
- libsodium AEAD guidance — https://libsodium.gitbook.io/doc/secret-key_cryptography/aead
- RFC 7914 (scrypt) — https://www.rfc-editor.org/rfc/rfc7914
- PQC Arena ML-KEM-768 benchmarks — https://www.qadvantage.io/pqc-arena/ml-kem-768
