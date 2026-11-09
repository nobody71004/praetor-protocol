# PRAETOR/1 — Rust implementation

Byte-compatible with the JavaScript reference in `../praetor`. The crate contains
PSEAL/1, PRAETOR/WIRE, PRAETOR/FAST, PRAETOR/BOLT, PRAETOR/PMARINE (experimental
PSEAL/2 envelope and fixed-cell channel on AEGIS-256), PRAETOR-HS/1 (X25519 +
ML-KEM-768), PRAETOR/CONTAINER, the PRAETOR/GUARD capability layer and a
native multiplexed TCP egress server.

## Toolchain

This workspace can carry a project-local Rust toolchain in `.toolchain/` (as
the development copy does). `cargo.sh` uses it when present and otherwise falls
back to the system `cargo`, so a fresh clone works with any recent Rust:

```bash
./cargo.sh build --release
./cargo.sh test
./cargo.sh run --release -- selftest
./cargo.sh run --release -- bench
```

`cargo.sh` sets `RUSTUP_HOME`/`CARGO_HOME` to the local toolchain and invokes
`cargo`. A normal `cargo` works too if you have one; nothing in the crate
requires the local copy.

`PRAETOR/BOLT` links the `aegis` crate's libaegis C backend, so the crate needs
a C compiler to build. On Windows MSVC, run the build from a Developer Command
Prompt, or set `CC=cl` with the MSVC `INCLUDE`/`LIB` environment; clang and gcc
work elsewhere. Without a C compiler the `aegis` build step fails.

## CLI

```bash
./cargo.sh run --release -- keygen --out demo.key
printf 'hello praetor' | ./cargo.sh run --release -- seal \
  --key demo.key --out msg.pseal
./cargo.sh run --release -- open --key demo.key --in msg.pseal

./cargo.sh run --release -- encrypt --key demo.key --in big.bin \
  --out big.praetor --pad 1048576
./cargo.sh run --release -- decrypt --key demo.key --in big.praetor --out big.out
```

`--pad` on `seal` writes a four-byte authenticated length frame inside the
padded plaintext; pass `--pad` to `open` to strip it. Container encryption
stores the real length in the authenticated header, so `decrypt` always
truncates padding automatically.

## Egress server

`praetor-egress` is a native exit that terminates PRAETOR/1 sessions and
forwards the multiplexed TCP streams. It uses the same 5-byte egress frame
protocol as `praetor/bin/praetor-egress.js`, so the existing Node proxy and
desktop client can use a Rust exit without changes.

The key file is the same base64 X-Wing server secret key used by the Node
exit (2,432 decoded bytes):

```bash
./cargo.sh run --release --bin praetor-egress -- \
  --key /path/to/server.key --host 0.0.0.0 --port 9443
```

It prints a JSON startup line and logs each session. Options: `--cell-size`
(default 1024), `--max-message-mib` (64), `--connect-timeout-ms` (10000) and
`--quiet`. The exit is PSEAL-only, like the Node implementation, and does not
authenticate individual clients.

## Tests

* `tests/vectors.rs` — byte-for-byte AEAD, Padmé and Shamir vectors, plus
  decapsulation of a ciphertext produced by the JS `@noble/post-quantum` build.
* `tests/roundtrip.rs` — full handshake and channel, tamper rejection,
  container roundtrip/truncation, policy binding, lockout, audit-chain edit
  detection, Shamir and PoW.

* `tests/egress.rs` — Rust egress server against a local echo target: full
  handshake, CONNECT/OK, 20 KB DATA fragmentation/reassembly, CLOSE, and a
  refused target returning ERROR without killing the session.

Current status: `46 passed` (9 roundtrip + 5 vectors + 4 fast + 6 bolt + 17
pmarine + 4 egress unit + 1 egress integration), release build. The roundtrip tests include atomic file decryption and single-use
admission tickets: a truncated container must not clobber the destination or
leave partial plaintext. The fast, bolt and pmarine tests cover fragmentation,
both calling conventions, tamper rejection, replay rejection, padding cells,
key separation and cell-geometry binding.

## Performance

Measured on the development machine (Windows x64, release):

| operation | result |
|---|---:|
| PSEAL seal, 1 MiB | 498.9 MiB/s |
| PSEAL open, 1 MiB | 570.8 MiB/s |
| ML-KEM-768 decapsulation (libcrux AVX2) | 68,309 ops/s |
| Full handshake | 3,487 ops/s |
| FAST 1 KiB roundtrips (zero-copy) | 3,223,207 ops/s |
| FAST 60 KB full path (zero-copy) | 4,346.0 MiB/s |
| BOLT 1 KiB roundtrips (zero-copy) | 3,875,218 ops/s |
| BOLT 60 KB full path (zero-copy) | 5,830.4 MiB/s |
| PMARINE seal, 1 KiB | 1,136.5 MiB/s |
| PMARINE open, 1 KiB | 1,011.8 MiB/s |
| PMARINE seal, 60 KB | 1,687.6 MiB/s |
| PMARINE open, 60 KB | 1,658.3 MiB/s |
| PMARINE seal, 1 MiB | 1,174.7 MiB/s |
| PMARINE open, 1 MiB | 1,184.4 MiB/s |

BOLT uses AEGIS-128L through the `aegis` crate; FAST uses `ring`'s
AES-256-GCM. PMARINE uses the same crate's AEGIS-256 with a 32-byte SIV and a
32-byte tag. `PmarineChannel` seals each fixed-size wire cell with a per-cell
nonce, counter and replay window; the JavaScript reference and desktop client
still negotiate PSEAL. In the same session BOLT beats userspace WireGuard by
3.98× on 1 KiB roundtrips and 4.47×
on 60 KB throughput, and beats FAST by 1.20× and 1.34×. The ML-KEM-768 handshake is now 0.86× (up from 0.60×) after switching
to libcrux's AVX2 implementation and reusing cached X25519 public keys in
decapsulation; X25519 DH is what remains. See
`../praetor/docs/BOLT.md` and `../praetor/docs/FAST.md` for the tradeoffs and
`../praetor/docs/BENCHMARKS.md` for methodology.

### AEGIS lane variants

`pmarine-aegis-bench` measures AEGIS-256, AEGIS-256X2 and AEGIS-256X4 through
PMARINE's SIV envelope and fixed-cell channel, alongside BOLT, and prints JSON:

```bash
./cargo.sh run --release --bin pmarine-aegis-bench
```

On this machine (i9-14900HX, VAES/AVX2), the parallel lanes do not close the
BOLT gap: at 1 KiB the channel is 0.15–0.16× BOLT for all three variants, and at
60 KB 0.16–0.17×. The serial SIV HMAC dominates the per-cell cost; X2/X4 only
speed up the AEGIS portion. PMARINE remains a stronger envelope, not a BOLT
competitor.

## Security notes

* The crate uses `chacha20poly1305`, `ring` (AES-256-GCM for PRAETOR/FAST),
  `aegis` (AEGIS-128L for BOLT and AEGIS-256 for PMARINE), `libcrux-ml-kem 0.0.11`,
  `x25519-dalek 2`, `sha3`, `hkdf`, `hmac` and `scrypt`. ML-KEM decapsulation is treated as
  infallible (implicit rejection); the handshake confirmation is the
  authentication check.
* `PRAETOR/FAST` is opt-in and deliberately weaker than PSEAL: no SIV, no
  per-cell key commitment, and a 32-bit nonce counter that fails closed after
  2^32 cells under one key.
* `PRAETOR/BOLT` is opt-in and deliberately weaker than PSEAL: a 128-bit
  AEGIS-128L key, no SIV, and a stateful 64-bit counter. It is key-committing,
  but PSEAL's independent commitment tag is stronger. FAST's and BOLT's wire
  formats are not in the JS reference.
* `PRAETOR/PMARINE` is an experimental PSEAL/2 profile: AEGIS-256 (RFC 10032)
  with a full 32-byte HMAC-SHA256 SIV used as the AEGIS nonce, re-derived after
  authenticated decryption as the independent commitment. AEGIS's built-in
  commitment is not full when an attacker controls the associated data
  (IACR 2023/1495; RFC 10032 §9.1.2), so PMARINE does not rely on it alone.
  It is Rust-only and not audited; the JS reference does not implement it, and
  the desktop PMARINE profile currently routes over PSEAL.
* All-zero X25519 public keys and shared secrets are rejected.
* This is a reference implementation, not independently audited, and not a
  FIPS 140-3 validated module. Treat "military-grade" as a procurement claim,
  not a certification.
