# Adversarial security review — PRAETOR/1

**Scope:** the JavaScript reference, the Rust implementation, the browser bundle,
the TCP transport and the container/CLI paths. This is a maintainer-run review,
not an independent audit or a cryptanalysis of the composition. It combines
manual inspection with negative tests that try to break authentication, replay
protection, policy enforcement and file handling.

## Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| V-01 | High | File decryption wrote plaintext chunks directly to the destination and only checked the final chunk afterwards. A truncated or forged container could leave partial plaintext on disk and could truncate an existing destination file before authentication failed. | **Fixed** in JS and Rust: decrypt to a sibling temp file, `fsync`, then rename only after every chunk authenticates; on failure remove the temp. Regression tests assert the destination is untouched and no temp file remains. |
| V-02 | Medium | JS X-Wing encapsulation accepted an all-zero X25519 public key and did not explicitly reject an all-zero shared secret. Backend behaviour varies; relying on it is fragile. | **Fixed** in JS: reject zero `pk_X` and zero `ss_X` in both encapsulation and decapsulation. Rust already rejected both. |
| V-03 | Medium | Proof-of-work admission tickets could be reused for their 30-second lifetime after one successful solution. | **Fixed**: the JS gate consumes `(challenge, counter)` once and returns `reused` thereafter; the Rust gate has the same single-use set. |
| V-04 | Medium | There was no maintained browser path, so browser callers would have to fork the protocol and could silently diverge from the wire format. | **Fixed**: an esbuild bundle of the same core modules with WebCrypto/Noble shims. `browser/test.mjs` checks parity; the demo was executed in Chromium: handshake, 11 fixed cells for 5 KB, PSEAL and container all passed. |
| V-05 | Low | Deterministic PSEAL mode leaks plaintext equality. | **Accepted and documented.** It is opt-in, never the default, and is intended only for idempotent tokens. |
| V-06 | Low | The audit log detects edits within the retained window but not truncation of the whole log; an attacker with filesystem access can drop the newest entries. | **Accepted and documented.** Export `head` to an external anchor/WORM store if truncation evidence matters. |
| V-07 | Info | A client/server `cellSize` mismatch fails authentication rather than negotiating. | **Verified fail-closed**; the transport test pins both sides to 512 bytes. Negotiation is deliberately absent because the cell size is a policy decision, not an attacker-controlled parameter. |
| V-08 | Info | JS/V8 is not constant-time; GC may copy secrets; no HSM integration. | **Accepted.** Use the Rust build where local side channels matter, and an HSM/KMS for production key custody. |

## What was checked

* Every PSEAL open path verifies the commitment tag before decryption and
  re-derives the SIV prefix from the plaintext.
* Handshake confirmations are transcript-bound; flipping any byte of the server
  hello is rejected. A party holding only the public key cannot finish.
* Container chunk AAD binds index and final flag; truncation, reorder and
  trailing-byte tests fail closed.
* Transport accepts only framed handshake messages, caps frame size at 1 MiB,
  and treats every later unit as one fixed-size cell.
* Capability purpose binding, quotas, lockout, canary alerts and audit-chain
  edits have negative tests.
* Browser bundle uses WebCrypto `getRandomValues` for randomness and Noble for
  SHA-2/SHA-3, HMAC, HKDF, scrypt, ChaCha20-Poly1305, X25519 and ML-KEM.

## Residual risk

The composition has not been cryptanalysed externally. The handshake has no
formal verification. The JS guard is an authorization layer only: a caller that
can read the process memory or master key bypasses it. Nothing here is FIPS
140-3 validated or CNSA 2.0 compliant. Treat this as a well-tested reference
design, not a certified product.
