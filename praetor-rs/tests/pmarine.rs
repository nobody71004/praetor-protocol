use aegis::aegis256::Aegis256;
use praetor::pmarine::{
    envelope_parts, open, seal, PmarineChannel, PmarineKey, CELL_OVERHEAD, DETERMINISTIC_OVERHEAD,
    NONCE_BYTES, OVERHEAD, SIV_BYTES, TAG_BYTES,
};
use praetor::wire::Received;

fn pair(cell_size: usize) -> (PmarineChannel, PmarineChannel) {
    (
        PmarineChannel::new([1u8; 32], [2u8; 32], cell_size, 64 << 20).unwrap(),
        PmarineChannel::new([2u8; 32], [1u8; 32], cell_size, 64 << 20).unwrap(),
    )
}

fn key() -> PmarineKey {
    PmarineKey::new(&[7u8; 32]).unwrap()
}

fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn pmarine_roundtrip_random() {
    let k = key();
    let pt = b"pmarine test payload";
    let aad = b"header";
    let env = k.seal_random(pt, aad).unwrap();
    assert_eq!(env.len(), OVERHEAD + pt.len());
    assert_eq!(k.open(&env, aad, false).unwrap(), pt.to_vec());
}

#[test]
fn pmarine_roundtrip_deterministic() {
    let k = key();
    let pt = b"deterministic payload";
    let aad = b"header";
    let a = k.seal(pt, aad, None).unwrap();
    let b = k.seal(pt, aad, None).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), DETERMINISTIC_OVERHEAD + pt.len());
    assert_eq!(k.open(&a, aad, true).unwrap(), pt.to_vec());
}

#[test]
fn pmarine_empty_plaintext() {
    let k = key();
    let env = k.seal_random(b"", b"").unwrap();
    assert_eq!(env.len(), OVERHEAD);
    assert_eq!(k.open(&env, b"", false).unwrap(), Vec::<u8>::new());

    let env = k.seal(b"", b"aad", None).unwrap();
    assert_eq!(env.len(), DETERMINISTIC_OVERHEAD);
    assert_eq!(k.open(&env, b"aad", true).unwrap(), Vec::<u8>::new());
}

#[test]
fn pmarine_random_nonces_differ() {
    let k = key();
    let a = k.seal_random(b"same", b"").unwrap();
    let b = k.seal_random(b"same", b"").unwrap();
    assert_ne!(a, b);
    assert_eq!(k.open(&a, b"", false).unwrap(), b"same".to_vec());
    assert_eq!(k.open(&b, b"", false).unwrap(), b"same".to_vec());
}

#[test]
fn pmarine_rejects_tamper() {
    let k = key();
    let env = k.seal_random(b"tamper me", b"aad").unwrap();
    for idx in [
        0,
        NONCE_BYTES + 1,
        env.len() - TAG_BYTES - 1,
        env.len() - 1,
    ] {
        let mut bad = env.clone();
        bad[idx] ^= 1;
        assert!(k.open(&bad, b"aad", false).is_err(), "index {idx}");
    }
}

#[test]
fn pmarine_rejects_wrong_aad_key_and_mode() {
    let k = key();
    let env = k.seal_random(b"secret", b"right").unwrap();
    assert!(k.open(&env, b"wrong", false).is_err());
    let other = PmarineKey::new(&[8u8; 32]).unwrap();
    assert!(other.open(&env, b"right", false).is_err());
    assert!(k.open(&env, b"right", true).is_err());
}

#[test]
fn pmarine_rejects_truncation_and_bad_key_length() {
    let k = key();
    assert!(k.open(&[], b"", false).is_err());
    assert!(PmarineKey::new(&[0u8; 31]).is_err());
    assert!(PmarineKey::new(&[0u8; 33]).is_err());
}

#[test]
fn pmarine_envelope_parts_roundtrip() {
    let k = key();
    let pt = b"parts";
    let env = k.seal_random(pt, b"aad").unwrap();
    let (nonce, siv, ct, tag) = envelope_parts(&env, false).unwrap();
    assert_eq!(nonce.len(), NONCE_BYTES);
    assert_eq!(siv.len(), SIV_BYTES);
    assert_eq!(ct.len(), pt.len());
    assert_eq!(tag.len(), TAG_BYTES);

    let env = k.seal(pt, b"aad", Some([9u8; NONCE_BYTES])).unwrap();
    let (nonce, _, _, _) = envelope_parts(&env, false).unwrap();
    assert_eq!(nonce, &[9u8; NONCE_BYTES]);
}

#[test]
fn pmarine_free_functions_roundtrip() {
    let env = seal(&[3u8; 32], b"free", b"aad", Some([4u8; NONCE_BYTES])).unwrap();
    assert_eq!(open(&[3u8; 32], &env, b"aad", false).unwrap(), b"free");
}

#[test]
fn pmarine_channel_roundtrip_and_fragmentation() {
    let (mut a, mut b) = pair(512);
    let msg = vec![0xab; 3000];
    let cells = a.send(&msg).unwrap();
    assert_eq!(cells.len(), 7);
    let mut out = None;
    for mut cell in cells {
        assert_eq!(cell.len(), CELL_OVERHEAD + 512);
        if let Received::Complete { data, .. } = b.receive(&mut cell).unwrap() {
            out = Some(data);
        }
    }
    assert_eq!(out.unwrap(), msg);
}

#[test]
fn pmarine_channel_buffer_api_roundtrip() {
    let (mut a, mut b) = pair(1024);
    let msg = vec![0x5a; 60_000];
    let mut wire = Vec::new();
    a.send_into(&msg, &mut wire).unwrap();
    assert_eq!(wire.len() % (CELL_OVERHEAD + 1024), 0);
    let mut out = None;
    for chunk in wire.chunks_mut(CELL_OVERHEAD + 1024) {
        if let Received::Complete { data, .. } = b.receive(chunk).unwrap() {
            out = Some(data);
        }
    }
    assert_eq!(out.unwrap(), msg);
}

#[test]
fn pmarine_channel_rejects_tamper() {
    let (mut a, mut b) = pair(256);
    let mut cell = a.send(b"tamper").unwrap().remove(0);
    let last = cell.len() - 1;
    cell[last] ^= 1;
    assert!(b.receive(&mut cell).is_err());
    // Fail closed: rejected ciphertext must not survive as candidate plaintext.
    assert!(cell.iter().all(|&x| x == 0));

    // A corrupted SIV must fail even when the AEGIS tag itself was untouched.
    let mut cell = a.send(b"tamper").unwrap().remove(0);
    cell[NONCE_BYTES + 1] ^= 1;
    assert!(b.receive(&mut cell).is_err());
}

#[test]
fn pmarine_channel_rejects_replay() {
    let (mut a, mut b) = pair(256);
    let mut cell = a.send(b"once").unwrap().remove(0);
    b.receive(&mut cell).unwrap();
    let mut replay = cell.clone();
    assert!(b.receive(&mut replay).is_err());
}

#[test]
fn pmarine_channel_padding_is_hidden_by_ciphertext() {
    let (mut a, mut b) = pair(256);
    let mut cell = a.send_padding().unwrap();
    assert_eq!(cell.len(), 256 + CELL_OVERHEAD);
    assert!(matches!(b.receive(&mut cell).unwrap(), Received::Padding));
}

#[test]
fn pmarine_channels_with_different_keys_do_not_interoperate() {
    let mut a = PmarineChannel::new([7u8; 32], [8u8; 32], 256, 1 << 20).unwrap();
    let mut b = PmarineChannel::new([9u8; 32], [10u8; 32], 256, 1 << 20).unwrap();
    let mut cell = a.send(b"secret").unwrap().remove(0);
    assert!(b.receive(&mut cell).is_err());
}

#[test]
fn pmarine_channel_rejects_wrong_cell_size_and_geometry() {
    let mut a = PmarineChannel::new([1u8; 32], [2u8; 32], 256, 1 << 20).unwrap();
    let mut b = PmarineChannel::new([2u8; 32], [1u8; 32], 512, 1 << 20).unwrap();
    let mut cell = a.send(b"geometry").unwrap().remove(0);
    assert!(b.receive(&mut cell).is_err());
    assert!(PmarineChannel::new([1u8; 32], [2u8; 32], 8, 1 << 20).is_err());
    assert!(PmarineChannel::new([1u8; 32], [2u8; 32], 65_536, 1 << 20).is_err());
}

/// RFC 10032 Appendix A.3.2, 256-bit tag. This pins the AEGIS-256 backend and
/// the 32-byte tag construction PMARINE relies on.
#[test]
fn pmarine_aegis256_rfc_vector() {
    let key: [u8; 32] =
        hex_arr("1001000000000000000000000000000000000000000000000000000000000000");
    let nonce: [u8; 32] =
        hex_arr("1000020000000000000000000000000000000000000000000000000000000000");
    let msg = [0u8; 16];
    let (ct, tag) = Aegis256::<32>::new(&key, &nonce).encrypt(&msg, b"");
    assert_eq!(hex::encode(ct), "754fc3d8c973246dcc6d741412a4b236");
    assert_eq!(
        hex::encode(tag),
        "1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13"
    );
}
