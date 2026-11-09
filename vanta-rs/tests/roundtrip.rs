use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use vanta::aead::SealKey;
use vanta::container;
use vanta::guard::{self, Policy, Vault};
use vanta::handshake;
use vanta::wire::{Received, SecureChannel};
use vanta::xwing;

#[test]
fn hybrid_handshake_and_channel() {
    let (server_pk, server_sk) = xwing::keygen();
    let (c1, mut cs) = handshake::client_init(&server_pk).unwrap();
    let (s1, mut ss) = handshake::server_respond(&server_sk, &c1).unwrap();
    let (confirm_c, client_session) = handshake::client_finish(&mut cs, &s1).unwrap();
    let server_session = handshake::server_finish(&mut ss, &confirm_c).unwrap();

    assert_eq!(client_session.send_chain, server_session.recv_chain);
    assert_eq!(client_session.recv_chain, server_session.send_chain);
    assert_eq!(client_session.session_id, server_session.session_id);

    let mut a = SecureChannel::new(
        client_session.send_chain,
        client_session.recv_chain,
        512,
        1024,
        64 << 20,
    )
    .unwrap();
    let mut b = SecureChannel::new(
        server_session.send_chain,
        server_session.recv_chain,
        512,
        1024,
        64 << 20,
    )
    .unwrap();

    let msg = vec![0xab; 3000];
    let cells = a.send(&msg).unwrap();
    let mut out = None;
    for cell in cells {
        if let Received::Complete { data, .. } = b.receive(&cell).unwrap() {
            out = Some(data);
        }
    }
    assert_eq!(out.unwrap(), msg);
}

#[test]
fn handshake_tamper_is_detected() {
    let (pk, sk) = xwing::keygen();
    let (c1, mut cs) = handshake::client_init(&pk).unwrap();
    let (mut s1, _ss) = handshake::server_respond(&sk, &c1).unwrap();
    s1[3] ^= 1;
    assert!(handshake::client_finish(&mut cs, &s1).is_err());
}

#[test]
fn envelope_tamper_and_wrong_key() {
    let key = [7u8; 32];
    let seal = SealKey::new(&key).unwrap();
    let env = seal.seal_random(b"secret", b"aad").unwrap();
    assert_eq!(seal.open(&env, b"aad", false).unwrap(), b"secret");
    let mut bad = env.clone();
    bad[42] ^= 1;
    assert!(seal.open(&bad, b"aad", false).is_err());
    let other = SealKey::new(&[8u8; 32]).unwrap();
    assert!(other.open(&env, b"aad", false).is_err());
}

#[test]
fn container_roundtrip_and_truncation() {
    let key = [3u8; 32];
    let pt: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
    let ct = container::encrypt_bytes(&pt, &key, 1024, Some(1 << 16), b"file").unwrap();
    let (back, header) = container::decrypt_bytes(&ct, &key).unwrap();
    assert_eq!(back, pt);
    assert_eq!(header.real_size as usize, pt.len());
    assert!(header.total_size as usize >= pt.len());
    assert!(container::decrypt_bytes(&ct[..ct.len() - 10], &key).is_err());
}

#[test]
fn file_decryption_is_atomic() {
    let dir = std::env::temp_dir().join(format!(
        "vanta-atomic-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let src = dir.join("in.bin");
    let ct = dir.join("in.vanta");
    let out = dir.join("out.bin");
    let key = [5u8; 32];
    let pt: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    fs::write(&src, &pt).unwrap();
    container::encrypt_file(&src, &ct, &key, 512, None, b"x").unwrap();
    let mut bad = fs::read(&ct).unwrap();
    bad.truncate(bad.len() - 10);
    fs::write(&ct, &bad).unwrap();
    fs::write(&out, b"sentinel").unwrap();
    assert!(container::decrypt_file(&ct, &out, &key).is_err());
    assert_eq!(fs::read(&out).unwrap(), b"sentinel");
    let leftover = fs::read_dir(&dir)
        .unwrap()
        .any(|e| e.unwrap().file_name().to_string_lossy().contains("vanta-tmp"));
    assert!(!leftover, "temporary plaintext must be removed");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn guard_purpose_binding_and_lockout() {
    let mut vault = Vault::new(b"audit-secret-0123456789").unwrap();
    let mut policy = Policy::default();
    policy.purposes = Some(vec!["read:config".into()]);
    policy.max_auth_failures = 2;
    policy.lockout_ms = 1000;
    vault.add("cap", &[9u8; 32], policy, 0).unwrap();
    let env = vault.seal("cap", b"db-password", "read:config", b"", 0).unwrap();
    assert_eq!(
        vault.open("cap", &env, "read:config", b"", 0).unwrap(),
        b"db-password"
    );
    assert!(vault.open("cap", &env, "read:customers", b"", 0).is_err());
    let mut bad = env.clone();
    bad[0] ^= 1;
    assert!(vault.open("cap", &bad, "read:config", b"", 0).is_err());
    assert!(vault.open("cap", &bad, "read:config", b"", 0).is_err());
    assert!(vault.open("cap", &env, "read:config", b"", 0).is_err());
    assert!(vault.audit.verify());
}

#[test]
fn guard_shamir_and_pow() {
    let secret = [42u8; 32];
    let shares = guard::shamir_split(&secret, 5, 3).unwrap();
    assert_eq!(guard::shamir_combine(&shares[..3]).unwrap(), secret);
    assert_ne!(guard::shamir_combine(&shares[..2]).unwrap(), secret);
    let challenge = [1u8; 32];
    let counter = guard::solve_challenge(&challenge, 8).unwrap();
    assert!(guard::verify_solution(&challenge, counter, 8));
    assert!(!guard::verify_solution(&challenge, counter, 12));
}

#[test]
fn admission_ticket_is_single_use() {
    let mut gate = guard::AdmissionGate::new(2, 2, 100);
    let ticket = gate.issue(0);
    let bits = ticket["bits"].as_u64().unwrap() as u32;
    let challenge = hex::decode(ticket["challenge"].as_str().unwrap()).unwrap();
    let counter = guard::solve_challenge(&challenge, bits).unwrap();
    assert!(gate.verify(&ticket, counter, 0));
    assert!(!gate.verify(&ticket, counter, 0));
}

#[test]
fn audit_chain_detects_edit() {
    let mut log = guard::AuditLog::new(b"0123456789abcdef").unwrap();
    log.append("open", 1, serde_json::json!({"id":"a"}));
    log.append("open", 2, serde_json::json!({"id":"b"}));
    assert!(log.verify());
    log.entries[0]["kind"] = serde_json::json!("rewritten");
    assert!(!log.verify());
}
