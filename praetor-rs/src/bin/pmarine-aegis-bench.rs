// PRAETOR PMARINE AEGIS lane-variant benchmark.
//
// Compares AEGIS-256, AEGIS-256X2 and AEGIS-256X4 through PMARINE's real SIV
// envelope and fixed-cell channel, alongside BOLT (AEGIS-128L), in one process
// on one machine. It prints JSON so the results can be archived and ratios
// computed mechanically. Each row is the median of three timed runs after
// warmup.
//
// Run with:
//   ./cargo.sh run --release --bin pmarine-aegis-bench

use std::hint::black_box;
use std::time::Instant;

use aegis::aegis256::Aegis256;
use aegis::aegis256x2::Aegis256X2;
use aegis::aegis256x4::Aegis256X4;
use praetor::bolt::{BoltChannel, BOLT_OVERHEAD};
use praetor::pmarine::{AegisVariant, PmarineChannel, PmarineKey, CELL_OVERHEAD, TAG_BYTES};
use praetor::util::hmac_sha256;
use praetor::wire::ReceivedRef;
use serde_json::json;

const KEY: [u8; 32] = [7u8; 32];
const AEAD_NONCE: [u8; 32] = [9u8; 32];
const AAD: &[u8] = b"bench";

fn median_rate(iters: usize, mut f: impl FnMut()) -> f64 {
    let mut rates = [0f64; 3];
    for slot in &mut rates {
        for _ in 0..3 {
            f();
        }
        let start = Instant::now();
        for _ in 0..iters {
            f();
        }
        *slot = iters as f64 / start.elapsed().as_secs_f64();
    }
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap());
    rates[1]
}

fn mib_s(bytes: usize, ops_s: f64) -> f64 {
    (bytes as f64 * ops_s) / (1024.0 * 1024.0)
}

fn iterations(size: usize) -> usize {
    if size >= 1_048_576 {
        64
    } else if size >= 60_000 {
        2_000
    } else {
        50_000
    }
}

fn aead_seal_once(variant: AegisVariant, pt: &[u8]) -> (Vec<u8>, [u8; TAG_BYTES]) {
    match variant {
        AegisVariant::Aegis256 => Aegis256::<TAG_BYTES>::new(&KEY, &AEAD_NONCE).encrypt(pt, AAD),
        AegisVariant::Aegis256X2 => {
            Aegis256X2::<TAG_BYTES>::new(&KEY, &AEAD_NONCE).encrypt(pt, AAD)
        }
        AegisVariant::Aegis256X4 => {
            Aegis256X4::<TAG_BYTES>::new(&KEY, &AEAD_NONCE).encrypt(pt, AAD)
        }
    }
}

fn aead_rows() -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    for variant in [
        AegisVariant::Aegis256,
        AegisVariant::Aegis256X2,
        AegisVariant::Aegis256X4,
    ] {
        for size in [1024usize, 60_000, 1_048_576] {
            let pt = vec![0u8; size];
            let iters = iterations(size);
            let (ct, tag) = aead_seal_once(variant, &pt);
            let seal_s = median_rate(iters, || {
                let out =
                    match variant {
                        AegisVariant::Aegis256 => Aegis256::<TAG_BYTES>::new(&KEY, &AEAD_NONCE)
                            .encrypt(black_box(&pt), AAD),
                        AegisVariant::Aegis256X2 => Aegis256X2::<TAG_BYTES>::new(&KEY, &AEAD_NONCE)
                            .encrypt(black_box(&pt), AAD),
                        AegisVariant::Aegis256X4 => Aegis256X4::<TAG_BYTES>::new(&KEY, &AEAD_NONCE)
                            .encrypt(black_box(&pt), AAD),
                    };
                black_box(out);
            });
            let open_s = median_rate(iters, || {
                let out = match variant {
                    AegisVariant::Aegis256 => Aegis256::<TAG_BYTES>::new(&KEY, &AEAD_NONCE)
                        .decrypt(black_box(&ct), &tag, AAD),
                    AegisVariant::Aegis256X2 => Aegis256X2::<TAG_BYTES>::new(&KEY, &AEAD_NONCE)
                        .decrypt(black_box(&ct), &tag, AAD),
                    AegisVariant::Aegis256X4 => Aegis256X4::<TAG_BYTES>::new(&KEY, &AEAD_NONCE)
                        .decrypt(black_box(&ct), &tag, AAD),
                };
                black_box(out.unwrap());
            });
            rows.push(json!({
                "variant": variant.label(),
                "size": size,
                "tag_bytes": TAG_BYTES,
                "seal_mib_s": mib_s(size, seal_s),
                "open_mib_s": mib_s(size, open_s),
                "seal_ops_s": seal_s,
                "open_ops_s": open_s,
            }));
        }
    }
    rows
}

fn envelope_rows() -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    let key = PmarineKey::new(&KEY).unwrap();
    let nonce = Some([5u8; 16]);
    for variant in [
        AegisVariant::Aegis256,
        AegisVariant::Aegis256X2,
        AegisVariant::Aegis256X4,
    ] {
        for size in [1024usize, 60_000, 1_048_576] {
            let pt = vec![0u8; size];
            let iters = iterations(size);
            let env = key.seal_with_variant(&pt, AAD, nonce, variant).unwrap();
            let seal_s = median_rate(iters, || {
                let out = key
                    .seal_with_variant(black_box(&pt), AAD, nonce, variant)
                    .unwrap();
                black_box(out);
            });
            let open_s = median_rate(iters, || {
                let out = key
                    .open_with_variant(black_box(&env), AAD, false, variant)
                    .unwrap();
                black_box(out);
            });
            rows.push(json!({
                "variant": variant.label(),
                "size": size,
                "overhead": praetor::pmarine::OVERHEAD,
                "seal_mib_s": mib_s(size, seal_s),
                "open_mib_s": mib_s(size, open_s),
                "seal_ops_s": seal_s,
                "open_ops_s": open_s,
            }));
        }
    }
    rows
}

fn siv_rows() -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    let nonce = [0u8; 16];
    for (label, size, aad) in [
        (
            "cell_1024",
            1024usize,
            b"PRAETOR/PMARINE/1\x04\x00".as_slice(),
        ),
        (
            "cell_65519",
            65_519usize,
            b"PRAETOR/PMARINE/1\xff\xef".as_slice(),
        ),
        ("envelope_1m", 1_048_576usize, b"bench".as_slice()),
    ] {
        let pt = vec![0u8; size];
        let alen = (aad.len() as u64).to_be_bytes();
        let plen = (size as u64).to_be_bytes();
        let iters = if size >= 1_048_576 {
            64
        } else if size >= 60_000 {
            2_000
        } else {
            20_000
        };
        let ops = median_rate(iters, || {
            black_box(hmac_sha256(
                &KEY,
                &[b"PMARINE/1/siv", &nonce, &alen, aad, &plen, &pt],
            ));
        });
        rows.push(json!({
            "scope": label,
            "size": size,
            "siv_ops_s": ops,
            "siv_mib_s": mib_s(size, ops),
        }));
    }
    rows
}

fn pmarine_cell_rows() -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    for variant in [
        AegisVariant::Aegis256,
        AegisVariant::Aegis256X2,
        AegisVariant::Aegis256X4,
    ] {
        for (size, cell_size) in [(1008usize, 1024usize), (60_000, 65_519)] {
            let cell_len = CELL_OVERHEAD + cell_size;
            let payload = vec![9u8; size];
            let iters = if size >= 60_000 { 2_000 } else { 20_000 };
            let mut scratch = Vec::with_capacity(cell_len * 2);
            let (mut a, mut b) = (
                PmarineChannel::new_with_variant(
                    [31u8; 32],
                    [32u8; 32],
                    cell_size,
                    64 << 20,
                    variant,
                )
                .unwrap(),
                PmarineChannel::new_with_variant(
                    [32u8; 32],
                    [31u8; 32],
                    cell_size,
                    64 << 20,
                    variant,
                )
                .unwrap(),
            );
            let mut run = || {
                scratch.clear();
                a.send_into(black_box(&payload), &mut scratch).unwrap();
                for chunk in scratch.chunks_mut(cell_len) {
                    if let ReceivedRef::Complete { data, .. } = b.receive_ref(chunk).unwrap() {
                        black_box(data);
                    }
                }
            };
            let ops = median_rate(iters, &mut run);
            rows.push(json!({
                "profile": format!("PMARINE/{}", variant.label()),
                "variant": variant.label(),
                "size": size,
                "cell_size": cell_size,
                "overhead": CELL_OVERHEAD,
                "ops_s": ops,
                "mib_s": mib_s(size, ops),
            }));
        }
    }
    rows
}

fn bolt_cell_rows() -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    for (size, cell_size) in [(1008usize, 1024usize), (60_000, 65_519)] {
        let cell_len = BOLT_OVERHEAD + cell_size;
        let payload = vec![9u8; size];
        let iters = if size >= 60_000 { 2_000 } else { 20_000 };
        let mut scratch = Vec::with_capacity(cell_len * 2);
        let (mut a, mut b) = (
            BoltChannel::new([41u8; 32], [42u8; 32], cell_size, 64 << 20).unwrap(),
            BoltChannel::new([42u8; 32], [41u8; 32], cell_size, 64 << 20).unwrap(),
        );
        let mut run = || {
            scratch.clear();
            a.send_into(black_box(&payload), &mut scratch).unwrap();
            for chunk in scratch.chunks_mut(cell_len) {
                if let ReceivedRef::Complete { data, .. } = b.receive_ref(chunk).unwrap() {
                    black_box(data);
                }
            }
        };
        let ops = median_rate(iters, &mut run);
        rows.push(json!({
            "profile": "BOLT/aegis128l",
            "variant": "aegis128l",
            "size": size,
            "cell_size": cell_size,
            "overhead": BOLT_OVERHEAD,
            "ops_s": ops,
            "mib_s": mib_s(size, ops),
        }));
    }
    rows
}

fn cpu_features() -> serde_json::Value {
    #[cfg(target_arch = "x86_64")]
    {
        json!({
            "aes": std::arch::is_x86_feature_detected!("aes"),
            "avx2": std::arch::is_x86_feature_detected!("avx2"),
            "vaes": std::arch::is_x86_feature_detected!("vaes"),
            "avx512f": std::arch::is_x86_feature_detected!("avx512f"),
        })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        json!({})
    }
}

fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "implementation": "praetor-rust",
            "benchmark": "pmarine-aegis-lanes",
            "target": format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            "cpu_features": cpu_features(),
            "aegis_backend": "libaegis C backend (runtime AES/VAES dispatch)",
            "aead": aead_rows(),
            "envelope": envelope_rows(),
            "siv_hmac": siv_rows(),
            "cells": pmarine_cell_rows(),
            "bolt_cells": bolt_cell_rows(),
        }))
        .unwrap()
    );
}
