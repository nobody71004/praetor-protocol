# PRAETOR vs WireGuard benchmark

This directory contains the same-machine comparison used for
`praetor/docs/benchmarks-praetor-vs-wireguard.svg`.

**WireGuard here is `boringtun` 0.7.1, Cloudflare's userspace WireGuard
library.** It performs the real NoiseIK handshake and transport encryption in
process. It is not the kernel WireGuard data path and there is no TUN, UDP or
routing in the measurement. The numbers are protocol CPU costs, not VPN
wall-clock throughput.

## Reproduce

```bash
# PRAETOR (Rust release, LTO)
cd praetor-rs
./cargo.sh run --release --bin protocol-bench > ../praetor/bench/results-praetor.json

# WireGuard userspace
cd ../praetor/bench/wireguard-bench
../../../praetor-rs/cargo.sh run --release > ../results-wireguard.json

# chart
cd ..
node chart-vs-wireguard.mjs
```

The chart generator reads the two measured JSON files and writes
`../docs/benchmarks-praetor-vs-wireguard.svg`. No values are typed by hand.

## What is measured

* Handshake: a complete handshake between two fresh peers, including the
  initiator and responder paths.
* 1 KiB roundtrips: one encapsulation and one decapsulation per iteration;
  for PRAETOR this is a full fixed cell through `SecureChannel`.
* 60 KB: the same roundtrip with a 60 KB payload. PRAETOR fragments it across
  1024-byte cells; WireGuard handles it as one transport packet.

## Why the numbers differ

PRAETOR is doing more work by design: a two-pass SIV prefix, an independent
32-byte commitment tag, an 80-byte envelope, fixed-size cell framing, and an
X25519 + ML-KEM-768 handshake. WireGuard's classical NoiseIK handshake has no
post-quantum component and no ciphertext commitment. The comparison is useful
for cost accounting, not for declaring one protocol "faster" in every sense.
