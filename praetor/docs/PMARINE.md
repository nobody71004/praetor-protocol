# PRAETOR/PMARINE (PSEAL/2)

`PRAETOR/PMARINE` is an experimental envelope profile for PRAETOR/1. It keeps
PSEAL's SIV construction and 80-byte envelope shape, but replaces
ChaCha20-Poly1305 plus the separate commitment HMAC with **AEGIS-256**
(RFC 10032) and a full 256-bit SIV.

It is **not** the default, **not** implemented in the JavaScript reference, and
**not independently audited**. The Rust crate now includes a fixed-cell
`PmarineChannel`; the JavaScript and desktop transports still use PSEAL. PMARINE
is a composition of standard primitives, not a new block cipher or permutation.

## Why this profile exists

PSEAL/1 is deliberately portable: ChaCha20-Poly1305 works well without AES
acceleration, and two HMAC-SHA-256 passes provide the SIV prefix and the
independent commitment tag. On AES-NI hardware that composition leaves a lot of
throughput unused.

AEGIS-256 is a standardized low-level AEAD with:

* a 256-bit key and a 256-bit nonce;
* a 128- or 256-bit authentication tag;
* AES-NI/ARM-crypto implementations through libaegis;
* a claimed 256-bit security level against plaintext and state recovery;
* key-committing behavior with an important associated-data caveat (below).

PMARINE uses AEGIS-256 with a **256-bit tag** and keeps a full **256-bit SIV**.
The SIV is the AEGIS nonce, so nonce-misuse resistance is retained: distinct
plaintexts under the same outer nonce produce distinct AEGIS nonces.

## Wire format

```
HKDF-SHA256(K, salt = "PRAETOR/1", info = "pmarine", L = 64)
    -> k_siv (32) || k_enc (32)

nonce = 16 random bytes                       (probabilistic)
nonce = ε                                     (deterministic)

siv = HMAC-SHA256(k_siv,
                  "PMARINE/1/siv" || nonce ||
                  u64(|aad|) || aad ||
                  u64(|pt|)  || pt)            // full 32 bytes

ct || tag = AEGIS-256(k_enc, nonce = siv, pt,
                      "PMARINE/1/aead" || aad) // 32-byte tag

envelope = nonce || siv || ct || tag
```

## Fixed-cell channel

`PmarineChannel` wraps each `PRAETOR/WIRE` cell in the envelope above:

```
nonce = 8-byte random channel prefix || 64-bit big-endian counter
siv   = HMAC-SHA256(k_siv, "PMARINE/1/siv" || nonce || ... || cell)
cell  = nonce || siv || AEGIS-256(k_enc, siv, cell, aad) || tag
```

The associated data binds the `PRAETOR/PMARINE/1` label and the negotiated cell
size, so a cell from a different geometry does not authenticate. The receiver
checks the AEGIS tag, re-derives the SIV from the recovered plaintext, then
admits the counter through a 4,096-entry replay window. `send_into` reuses a
caller-owned buffer and `receive_ref` borrows plaintext from the decrypted cell;
the owned `send`/`receive` helpers are convenience wrappers. The channel is
implemented and tested in Rust only; it is not wired into the JS reference or
the desktop client.

Overhead is **80 bytes** probabilistic and **64 bytes** deterministic, the same
as PSEAL/1. The difference is internal: PSEAL carries a 16-byte SIV prefix, a
16-byte Poly1305 tag and a 32-byte commitment tag; PMARINE carries a 32-byte
SIV and a 32-byte AEGIS tag.

### Open

1. Check the minimum length: 80 bytes probabilistic, 64 deterministic.
2. Split `nonce`, `siv`, `ct`, `tag`.
3. Verify the AEGIS-256 tag and decrypt in place. A failure returns `AUTH_FAILED`
   and the candidate plaintext is zeroised; no plaintext is released.
4. Recompute `siv` from the recovered plaintext, `aad` and `nonce`; compare in
   constant time. A mismatch returns `AUTH_FAILED` and zeroises the plaintext.

The SIV check is the independent commitment. It does not rely on AEGIS's
built-in key commitment.

## Differential profile

| Property | PSEAL/1 | PMARINE/1 |
|---|---|---|
| Inner AEAD | ChaCha20-Poly1305 (RFC 8439) | AEGIS-256 (RFC 10032) |
| Key material | 256-bit master → `k_siv`, `k_enc`, `k_com` | 256-bit master → `k_siv`, `k_enc` |
| SIV | 16-byte HMAC prefix | 32-byte HMAC SIV |
| AEAD nonce | 96-bit SIV prefix | 256-bit SIV |
| Authentication tag | 128-bit Poly1305 + 256-bit commitment HMAC | 256-bit AEGIS tag |
| Commitment check | `k_com` tag before decryption | 32-byte SIV re-derived after AEGIS authentication |
| Nonce-misuse resistance | Yes (SIV) | Yes (SIV) |
| Probabilistic overhead | 80 bytes | 80 bytes |
| Deterministic overhead | 64 bytes | 64 bytes |
| AES acceleration | Not required | Strongly preferred |
| JS reference | Yes | No |
| Status | Default, unaudited | Experimental, unaudited |

PMARINE is not automatically stronger than PSEAL. It is a different trade:
AEGIS-256 gives a 256-bit key/nonce/tag and much higher throughput on AES-NI,
while PSEAL remains the portable default and has a longer review history.

## Key commitment and the AEGIS caveat

AEGIS is described as key-committing, and a 256-bit tag raises the claimed
committing security to about 128 bits. But RFC 10032 §9.1.2 says AEGIS is fully
committing only in the restricted setting where the adversary cannot control the
associated data. With control of `ad`, Isobe and Rahman found an O(1) attack
that produces multiple keys verifying the same authenticated ciphertext
(IACR ePrint 2023/1495).

PMARINE therefore does **not** treat the AEGIS tag as its commitment. It
retains an independent 32-byte SIV computed under `k_siv` over
`(nonce, aad, pt)`. For two keys to make the same envelope decrypt to different
plaintexts, they would have to collide in both the AEGIS tag and the SIV; the SIV
collision alone is a 256-bit MAC collision (about 2^128 work by the birthday
bound). Both failure paths return the same `AUTH_FAILED` error, so the API does
not expose which check failed.

The ordering is different from PSEAL/1: PMARINE cannot check the SIV before
decryption because the SIV is the AEAD nonce. The AEGIS tag is verified before
any plaintext is released, and the SIV check is a second gate. A forged AEGIS
tag must already pass a 256-bit tag check (at least 128-bit forgery security
under RFC 10032); a valid AEGIS ciphertext with the wrong SIV is then rejected
without returning plaintext.

## Limits and caveats

* **AEGIS-256 is standardized; the PMARINE composition is not audited.** The
  primitives are named and analysed, but this profile has not had independent
  review. Do not treat it as production-hardened.
* **Maximum message and AAD:** 2^61 − 1 bytes, the AEGIS-256 limit.
* **Key rotation:** rotate well before 2^64 envelopes. The 32-byte SIV and
  32-byte tag both target about 128-bit collision/forgery security.
* **Deterministic mode leaks equality.** Equal `(pt, aad)` produce equal
  envelopes. That is the SIV trade-off, not a bug.
* **Outer nonce reuse is safe** for confidentiality and integrity; a repeated
  outer nonce with different plaintext produces a different SIV/AEGIS nonce.
  Reusing the same `(pt, aad, nonce)` produces the same envelope by design.
* **AES acceleration matters.** libaegis falls back to software AES without
  AES-NI/ARM crypto; PMARINE can then be slower than PSEAL.
* **Rust-only channel.** The JS reference, browser bundle and desktop client do
  not implement PMARINE. The desktop PMARINE profile is a routing preset over
  PSEAL, not a PMARINE session.
* **Fixed-cell channel is Rust-only.** `PmarineChannel` exists and is tested in
  the Rust crate; `SecureChannel` in the JS reference still uses PSEAL/1.

## Measured performance

Same machine (Intel i9-14900HX), Windows x64, Rust release build, single thread.
Medians of three runs in one session. The PSEAL columns are from the same
session, not the older PSEAL table in `BENCHMARKS.md`.

| operation | bytes | PSEAL MiB/s | PMARINE MiB/s | speedup |
|---|---:|---:|---:|---:|
| seal | 1,024 | 301.1 | **1,136.5** | **3.77×** |
| open | 1,024 | 294.8 | **1,011.8** | **3.43×** |
| seal | 60,000 | 473.6 | **1,687.6** | **3.56×** |
| open | 60,000 | 619.6 | **1,658.3** | **2.68×** |
| seal | 1,048,576 | 485.5 | **1,174.7** | **2.42×** |
| open | 1,048,576 | 553.9 | **1,184.4** | **2.14×** |

The SIV HMAC is now the dominant cost; the AEGIS-256 pass itself is much
faster. PMARINE therefore beats PSEAL but remains below the SIV-free FAST and
BOLT transport profiles. Its purpose is a stronger default envelope, not the
fastest possible cell cipher.

## Reproduce

```bash
cd praetor-rs
./cargo.sh test --release --test pmarine
./cargo.sh test --release
./cargo.sh run --release --bin protocol-bench
./cargo.sh run --release -- selftest
```

`protocol-bench` prints a `pmarine` envelope array with `seal_mib_s`,
`open_mib_s` and `roundtrip_mib_s`, plus a `pmarine_cells` array for the
fixed-cell channel at 1 KiB and 60 KB.

## References

* RFC 10032, *The AEGIS Authenticated Encryption Algorithms* —
  https://www.rfc-editor.org/rfc/rfc10032.html
* T. Isobe and M. Rahman, *Key Committing Security Analysis of AEGIS*,
  IACR ePrint 2023/1495 — https://eprint.iacr.org/2023/1495
* RFC 9771, *Properties of AEAD Algorithms* —
  https://www.rfc-editor.org/rfc/rfc9771.html
* RFC 5297, *Synthetic Initialization Vector (SIV)* —
  https://www.rfc-editor.org/rfc/rfc5297
* RFC 8439, *ChaCha20 and Poly1305 for IETF Protocols* —
  https://www.rfc-editor.org/rfc/rfc8439
* libaegis — https://github.com/aegis-aead/libaegis
* `aegis` Rust crate — https://docs.rs/aegis
