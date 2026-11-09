# PRAETOR/BOLT

`PRAETOR/BOLT` is the fastest opt-in transport profile. It keeps the
post-quantum handshake and the fixed-cell framing, and replaces the per-cell
AEAD with **AEGIS-128L**.

BOLT is **not** the default and it is weaker than PSEAL. Use it when transport
throughput dominates and a 128-bit key with no SIV is acceptable.

## Measured result

Same machine (Intel i9-14900HX), single thread, Rust release builds, median of
three runs in one session. WireGuard is Cloudflare `boringtun` 0.7.1 userspace.
All PRAETOR transport rows use the same zero-copy buffer API as boringtun:
build the wire bytes in a reused buffer, then borrow the plaintext back out.

| Metric | PSEAL | FAST | BOLT | WireGuard | BOLT / WG |
|---|---:|---:|---:|---:|---:|
| 1 KiB authenticated roundtrips/s | 147,264 | 3,223,207 | **3,875,218** | 973,084 | **3.98×** |
| 60 KB full-path throughput | 143.1 MiB/s | 4,346.0 MiB/s | **5,830.4 MiB/s** | 1,303.8 MiB/s | **4.47×** |
| Full handshakes/s | 2,611 | 2,611 | 2,611 | 4,317 | 0.60× |

BOLT is **1.20× FAST at 1 KiB** and **1.34× FAST at 60 KB** under the same
calling convention. The 60 KB row measured 5,812–5,976 MiB/s across the three
runs; 5830.4 is the median.

Calling-convention sensitivity, same session:

| BOLT path | 1 KiB roundtrips/s | 60 KB MiB/s |
|---|---:|---:|
| caller buffer + zero-copy receive | 3,875,218 | 5,830.4 |
| caller buffer + owned receive | 3,578,458 | 5,276.2 |
| `Vec<Vec<u8>>` convenience API | 2,606,169 | 4,734.7 |

## Why AEGIS is faster

AEGIS-128L keeps eight 128-bit state blocks and absorbs 32 bytes per step with
eight AES rounds that are independent of each other. That gives the CPU eight
parallel AES dependency chains. AES-GCM's counter mode needs one AES round per
16-byte block and keeps only a handful of blocks in flight, and GHASH adds
CLMUL work on top. On hardware with AES-NI, AEGIS therefore turns the same AES
unit into several times the throughput.

The bottleneck moved twice while building these profiles:

1. **RustCrypto `aes-gcm`** ran GHASH on a portable path and capped FAST near
   700 MiB/s.
2. **`ring` AES-256-GCM** removed that cap; FAST became AEAD-bound near
   3.3 GiB/s.
3. **AEGIS-128L** removed the GCM structural limit; BOLT's full path, including
   cell packing, AEAD, parsing and replay checks, still reaches 5.8 GiB/s.

The remaining cost at 1 KiB is framing, not cryptography: one cell is one
16-byte header pack, one 1,024-byte encryption, one tag check and one parse.

## Wire format

```
nonce (16) = random 8-byte channel prefix || 64-bit big-endian counter
body  (N)  = AEGIS-128L ciphertext of one fixed-size packed cell
tag   (16)
```

* Overhead: **32 bytes** per cell (PSEAL 80, FAST 28).
* Every cell is padded to the configured cell size before encryption.
* AAD binds the profile label and the negotiated cell size.
* Receive authenticates and decrypts in place, then borrows the payload
  directly out of the caller's buffer.
* The 64-bit counter removes FAST's 2^32-cell key limit; BOLT can address
  2^64 cells under one key.
* Replay is rejected with a bounded window over the counter.

The AEGIS key is derived from the channel's 256-bit key material with
HKDF-SHA256 and the `PRAETOR/BOLT/1` label, so BOLT and PSEAL never share key
material.

## Security tradeoffs

BOLT gives up, relative to PSEAL:

* **No SIV / nonce-misuse resistance.** Reusing a 16-byte nonce under one key
  breaks AEGIS. The counter is stateful and must never repeat.
* **A 128-bit key.** AEGIS-128L targets 128-bit security; PSEAL uses
  ChaCha20-Poly1305 with 256-bit keys.
* **No independent commitment tag.** AEGIS is described as key-committing,
  which GCM is not, but PSEAL's separate 32-byte commitment tag is the stronger
  construction.
* **Rust-only.** The JS reference and browser bundle do not implement BOLT.

BOLT keeps the handshake, transcript binding, fixed-cell metadata hiding,
replay rejection and fail-closed authentication. On a bad tag the plaintext
buffer is zeroed before returning.

This is a reference implementation. AEGIS-128L is standardized as
ISO/IEC 29192-8 and the `aegis` crate uses the libaegis C backend, but PRAETOR/1
as a whole has not been independently audited.

## Hardware and build requirements

* **AES acceleration matters.** The speedup comes from AES-NI (x86) or the ARM
  crypto extensions. libaegis falls back to a software AES path without them;
  on such hardware BOLT can be slower than PSEAL. PSEAL remains the portable
  default.
* **A C compiler is required.** The `aegis` crate compiles libaegis. On
  Windows MSVC, build from a Developer Command Prompt (or set `CC=cl` with the
  MSVC `INCLUDE`/`LIB` environment); clang and gcc work elsewhere. Without a C
  compiler the crate does not build.

## Reproduce

```bash
cd praetor-rs
./cargo.sh test --release --test bolt
./cargo.sh run --release --bin protocol-bench
```

`protocol-bench` prints JSON containing `bolt_cells` for the three calling
conventions. The WireGuard side is the `_wg-bench` harness (`boringtun` 0.7.1),
which performs a real NoiseIK handshake and transport encryption in process.
Neither side includes a TUN device, UDP socket, routing or syscalls: these are
protocol CPU costs, not VPN wall-clock.
