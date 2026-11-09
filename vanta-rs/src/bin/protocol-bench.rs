// VANTA Rust benchmark used for the WireGuard comparison chart.
// Prints JSON so the chart generator consumes measured values only.
use std::hint::black_box;
use std::time::Instant;

use serde_json::json;
use vanta::aead::SealKey;
use vanta::handshake;
use vanta::wire::{Received, SecureChannel};

fn rate(iters: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..3 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    iters as f64 / start.elapsed().as_secs_f64()
}

fn main() {
    let (server_pk, server_sk) = vanta::xwing::keygen();
    let hs_iters = 300usize;
    let hs = rate(hs_iters, || {
        let (c1, mut cs) = handshake::client_init(&server_pk).unwrap();
        let (s1, mut ss) = handshake::server_respond(&server_sk, &c1).unwrap();
        let (confirm, _) = handshake::client_finish(&mut cs, &s1).unwrap();
        black_box(handshake::server_finish(&mut ss, &confirm).unwrap());
    });

    let key = [7u8; 32];
    let seal = SealKey::new(&key).unwrap();
    let mut transport = Vec::new();
    for size in [1024usize, 60000, 1_048_576] {
        let pt = vec![0u8; size];
        let env = seal.seal_random(&pt, b"bench").unwrap();
        let iters = if size >= 1_048_576 { 64 } else { 4000 };
        let seal_s = rate(iters, || {
            black_box(seal.seal_random(black_box(&pt), b"bench").unwrap());
        });
        let open_s = rate(iters, || {
            black_box(seal.open(black_box(&env), b"bench", false).unwrap());
        });
        transport.push(json!({
            "size": size,
            "seal_mib_s": (size as f64 * seal_s) / (1024.0 * 1024.0),
            "open_mib_s": (size as f64 * open_s) / (1024.0 * 1024.0),
            "roundtrip_mib_s": (size as f64) / ((1.0 / seal_s) + (1.0 / open_s)) / (1024.0 * 1024.0),
        }));
    }

    // Full fixed-cell path: fragment, seal every cell, authenticate and
    // reassemble. The 1 KiB row is one cell; the 60 KB row exercises framing.
    let chain_a = [1u8; 32];
    let chain_b = [2u8; 32];
    let mut a = SecureChannel::new(chain_a, chain_b, 1024, 1024, 64 << 20).unwrap();
    let mut b = SecureChannel::new(chain_b, chain_a, 1024, 1024, 64 << 20).unwrap();
    let mut cells = Vec::new();
    for size in [1008usize, 60_000] {
        let payload = vec![9u8; size];
        let iters = if size >= 60_000 { 2000 } else { 50_000 };
        let start = Instant::now();
        for _ in 0..iters {
            for cell in a.send(&payload).unwrap() {
                if let Received::Complete { data, .. } = b.receive(&cell).unwrap() {
                    black_box(data);
                }
            }
        }
        let secs = start.elapsed().as_secs_f64();
        let ops = iters as f64 / secs;
        cells.push(json!({
            "size": size,
            "ops_s": ops,
            "mib_s": (size as f64 * ops) / (1024.0 * 1024.0),
        }));
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "implementation": "vanta-rust",
            "cpu": "same machine, single thread",
            "handshake_ops_s": hs,
            "cells": cells,
            "transport": transport,
        }))
        .unwrap()
    );
}
