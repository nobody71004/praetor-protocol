use std::hint::black_box;
use std::time::Instant;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::OsRng;
use serde_json::json;

fn pair() -> (Tunn, Tunn) {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_public = PublicKey::from(&a_secret);
    let b_public = PublicKey::from(&b_secret);
    (
        Tunn::new(a_secret, b_public, None, None, 1, None),
        Tunn::new(b_secret, a_public, None, None, 2, None),
    )
}

fn handshake(a: &mut Tunn, b: &mut Tunn) -> bool {
    let mut buf = [0u8; 2048];
    let init = match a.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        _ => return false,
    };
    let resp = match b.decapsulate(None, &init, &mut buf) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        _ => return false,
    };
    matches!(
        a.decapsulate(None, &resp, &mut buf),
        TunnResult::Done | TunnResult::WriteToNetwork(_)
    )
}

fn ipv4_packet(size: usize) -> Vec<u8> {
    let mut p = vec![0u8; size];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 0, 0, 1]);
    p[16..20].copy_from_slice(&[10, 0, 0, 2]);
    p
}

fn roundtrip(a: &mut Tunn, b: &mut Tunn, packet: &[u8], out: &mut [u8], back: &mut [u8]) -> bool {
    let n = match a.encapsulate(packet, out) {
        TunnResult::WriteToNetwork(p) => p.len(),
        _ => return false,
    };
    match b.decapsulate(None, &out[..n], back) {
        TunnResult::WriteToTunnelV4(p, _) => p.len() == packet.len(),
        TunnResult::WriteToTunnelV6(p, _) => p.len() == packet.len(),
        _ => false,
    }
}

fn main() {
    // Fresh pairs only: a Tunn that already has a session will not initiate a
    // second handshake unless forced, which would make the timing meaningless.
    let hs_n = 400usize;
    let mut pairs: Vec<(Tunn, Tunn)> = (0..hs_n).map(|_| pair()).collect();
    let start = Instant::now();
    for (a, b) in pairs.iter_mut() {
        black_box(handshake(a, b));
    }
    let hs_secs = start.elapsed().as_secs_f64();
    let handshakes = hs_n as f64 / hs_secs;

    let (mut a, mut b) = pair();
    assert!(handshake(&mut a, &mut b), "wireguard handshake failed");

    let mut small = Vec::new();
    for size in [1024usize, 60000] {
        let packet = ipv4_packet(size);
        let mut out = vec![0u8; size + 64];
        let mut back = vec![0u8; size + 64];
        for _ in 0..3 {
            assert!(roundtrip(&mut a, &mut b, &packet, &mut out, &mut back));
        }
        let iters = if size >= 60000 { 2000 } else { 20000 };
        let start = Instant::now();
        for _ in 0..iters {
            assert!(roundtrip(&mut a, &mut b, &packet, &mut out, &mut back));
        }
        let secs = start.elapsed().as_secs_f64();
        let ops = iters as f64 / secs;
        small.push(json!({
            "size": size,
            "ops_s": ops,
            "mib_s": (size * iters) as f64 / secs / (1024.0 * 1024.0),
        }));
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "implementation": "wireguard-boringtun-0.7.1",
            "cpu": "same machine, single thread",
            "handshake_ops_s": handshakes,
            "transport": small,
        }))
        .unwrap()
    );
}
