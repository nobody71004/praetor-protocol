# PRAETOR/FAST

`PRAETOR/FAST` is an opt-in transport profile for PRAETOR/1. It keeps the
post-quantum handshake and the fixed-cell framing, and replaces the PSEAL
envelope with a single in-place AES-256-GCM pass per cell.

It is **not** the default and it is **weaker than PSEAL**. Use it when
throughput matters more than nonce-misuse resistance and ciphertext commitment.
For the fastest profile, see [`BOLT.md`](BOLT.md); BOLT uses AEGIS-128L and is a
further 1.20× (1 KiB) to 1.34× (60 KB) faster than FAST.

## Measured result

Same machine, single thread, Rust release builds, median of three runs in one
session. WireGuard is Cloudflare `boringtun` 0.7.1 userspace. Transport rows use
the same zero-copy buffer API as boringtun.

| Metric | PSEAL | FAST | WireGuard | FAST / WG |
|---|---:|---:|---:|---:|
| 1 KiB authenticated roundtrips/s | 147,264 | 3,223,207 | 973,084 | **3.31×** |
| 60 KB full-path throughput | 143.1 MiB/s | 4,346.0 MiB/s | 1,303.8 MiB/s | **3.33×** |
| Full handshakes/s | 2,611 | 2,611 | 4,317 | 0.60× |

The handshake gap does not close. It is not affected by the envelope: both
profiles run X25519 + ML-KEM-768 with two encapsulations and two
decapsulations, while WireGuard runs X25519 alone.

## Why WireGuard was ahead

The first FAST build lost to WireGuard: 0.72× at 1 KiB and 0.60× at 60 KB,
despite using AES-256-GCM. Profiling isolated two separate causes.

**1. The AEAD backend, which was the whole story at 60 KB.** The first build
linked RustCrypto `aes-gcm` 0.10. On this target its GHASH path is far slower
than AES-NI, and the combined AEAD topped out near 700 MiB/s. `boringtun`
links `ring`, whose AES-NI/CLMUL assembly runs the same cipher at roughly
3.3 GiB/s here. FAST now uses `ring`'s AES-256-GCM — the same backend
WireGuard uses — with an unchanged wire format. No primitive, key schedule or
framing changed.

Measured effect of that substitution, plus the zero-copy API added later:

| FAST build | 1 KiB roundtrips/s | 60 KB MiB/s |
|---|---:|---:|
| RustCrypto `aes-gcm`, owned API | 619,798 | 659.1 |
| `ring` AES-256-GCM, owned API | 2,412,138 | 4,029.9 |
| `ring` AES-256-GCM, zero-copy API | 3,223,207 | 4,346.0 |

**2. Per-cell overhead, which matters at 1 KiB.** A fixed cell is one AEAD
pass over a pre-sized buffer plus a 16-byte header pack; there is no IP header
parse, route lookup or per-packet session transition. The zero-copy API also
removes the per-cell allocation and payload copy that the first benchmark
included.

**3. AEAD choice.** AES-256-GCM with AES-NI and CLMUL is faster than
ChaCha20-Poly1305 on this CPU. WireGuard uses ChaCha20 because it is
constant-time and fast without AES acceleration. The advantage is therefore
hardware-dependent: on a CPU without AES-NI, FAST falls back to ring's
constant-time AES and the advantage shrinks or disappears.

## Wire format

```
nonce (12) = random 8-byte channel prefix || 32-bit big-endian counter
body  (N)  = AES-256-GCM ciphertext of one fixed-size packed cell
tag   (16)
```

* Overhead: **28 bytes** per cell, versus 80 bytes for PSEAL.
* Every cell is padded to the configured cell size before encryption, so the
  ciphertext length hides payload length exactly as in PSEAL.
* AAD binds the profile label and the negotiated cell size.
* Receive authenticates and decrypts in place; the payload can be borrowed
  directly from the caller's buffer.
* Replay is rejected with a bounded window over the 32-bit counter.

## Security tradeoffs

FAST gives up, relative to PSEAL:

* **No SIV / nonce-misuse resistance.** Reusing a nonce under one key is
  catastrophic for GCM. The counter is stateful and must never repeat.
* **No per-cell key commitment.** A ciphertext is not bound to one key with an
  independent commitment tag; PSEAL's 32-byte commitment tag provides that.
* **A hard key lifetime.** The counter is 32 bits, so a key fails closed after
  `2^32` cells. Rekey well before the limit, or use BOLT, whose 64-bit counter
  removes the cap.
* **No JS implementation.** FAST exists only in the Rust crate; the JS
  reference and browser bundle do not implement this profile.

FAST keeps the handshake, transcript binding, fixed-cell metadata hiding,
replay rejection and fail-closed authentication. It does not weaken the
post-quantum key exchange.

`ring`'s AES-256-GCM is constant-time and widely deployed, but PRAETOR/1 as a
whole is a reference implementation and has not been independently audited.

## Reproduce

```bash
cd praetor-rs
./cargo.sh test --release --test fast
./cargo.sh run --release --bin protocol-bench
```

The WireGuard side of the comparison is the `_wg-bench` harness
(`boringtun 0.7.1`), which performs a real NoiseIK handshake and transport
encryption in process. Neither side includes a TUN device, UDP socket,
routing or syscalls: these are protocol CPU costs, not VPN wall-clock.
