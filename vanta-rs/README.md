# VANTA/1 — Rust implementation

Byte-compatible with the JavaScript reference in `../vanta`. The crate contains
VSEAL/1, VANTA/WIRE, VANTA-HS/1 (X25519 + ML-KEM-768), VANTA/CONTAINER and the
VANTA/GUARD capability layer.

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

## CLI

```bash
./cargo.sh run --release -- keygen --out demo.key
printf 'hello vanta' | ./cargo.sh run --release -- seal \
  --key demo.key --out msg.vseal
./cargo.sh run --release -- open --key demo.key --in msg.vseal

./cargo.sh run --release -- encrypt --key demo.key --in big.bin \
  --out big.vanta --pad 1048576
./cargo.sh run --release -- decrypt --key demo.key --in big.vanta --out big.out
```

`--pad` on `seal` writes a four-byte authenticated length frame inside the
padded plaintext; pass `--pad` to `open` to strip it. Container encryption
stores the real length in the authenticated header, so `decrypt` always
truncates padding automatically.

## Tests

* `tests/vectors.rs` — byte-for-byte AEAD, Padmé and Shamir vectors, plus
  decapsulation of a ciphertext produced by the JS `@noble/post-quantum` build.
* `tests/roundtrip.rs` — full handshake and channel, tamper rejection,
  container roundtrip/truncation, policy binding, lockout, audit-chain edit
  detection, Shamir and PoW.

Current status: `14 passed` (9 roundtrip + 5 vectors), release build. The
roundtrip tests include atomic file decryption and single-use admission
tickets: a truncated container must not clobber the destination or leave
partial plaintext.

## Performance

Measured on the development machine (Windows x64, release):

| operation | result |
|---|---:|
| VSEAL seal, 1 MiB | 423.5 MiB/s |
| VSEAL open, 1 MiB | 464.2 MiB/s |
| X-Wing decapsulation | 10,364 ops/s |
| Full handshake | 2,116 ops/s |

See `../vanta/docs/BENCHMARKS.md` for methodology and the JS comparison.

## Security notes

* The crate uses `chacha20poly1305`, `ml-kem 0.2.3`, `x25519-dalek 2`,
  `sha3`, `hkdf`, `hmac` and `scrypt`. ML-KEM decapsulation is treated as
  infallible (implicit rejection); the handshake confirmation is the
  authentication check.
* All-zero X25519 public keys and shared secrets are rejected.
* This is a reference implementation, not independently audited, and not a
  FIPS 140-3 validated module. Treat "military-grade" as a procurement claim,
  not a certification.
