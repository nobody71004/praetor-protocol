use praetor::bolt::{BoltChannel, BOLT_OVERHEAD};
use praetor::wire::Received;

fn pair(cell_size: usize) -> (BoltChannel, BoltChannel) {
    (
        BoltChannel::new([1u8; 32], [2u8; 32], cell_size, 64 << 20).unwrap(),
        BoltChannel::new([2u8; 32], [1u8; 32], cell_size, 64 << 20).unwrap(),
    )
}

#[test]
fn bolt_channel_roundtrip_and_fragmentation() {
    let (mut a, mut b) = pair(512);
    let msg = vec![0xab; 3000];
    let cells = a.send(&msg).unwrap();
    assert_eq!(cells.len(), 7);
    let mut out = None;
    for mut cell in cells {
        if let Received::Complete { data, .. } = b.receive(&mut cell).unwrap() {
            out = Some(data);
        }
    }
    assert_eq!(out.unwrap(), msg);
}

#[test]
fn bolt_channel_buffer_api_roundtrip() {
    let (mut a, mut b) = pair(1024);
    let msg = vec![0x5a; 60_000];
    let mut wire = Vec::new();
    a.send_into(&msg, &mut wire).unwrap();
    assert_eq!(wire.len() % (BOLT_OVERHEAD + 1024), 0);
    let mut out = None;
    for chunk in wire.chunks_mut(BOLT_OVERHEAD + 1024) {
        if let Received::Complete { data, .. } = b.receive(chunk).unwrap() {
            out = Some(data);
        }
    }
    assert_eq!(out.unwrap(), msg);
}

#[test]
fn bolt_channel_rejects_tamper() {
    let (mut a, mut b) = pair(256);
    let mut cell = a.send(b"tamper").unwrap().remove(0);
    let last = cell.len() - 1;
    cell[last] ^= 1;
    assert!(b.receive(&mut cell).is_err());
    // Fail closed: rejected ciphertext must not survive as candidate plaintext.
    assert!(cell.iter().all(|&x| x == 0));
}

#[test]
fn bolt_channel_rejects_replay() {
    let (mut a, mut b) = pair(256);
    let mut cell = a.send(b"once").unwrap().remove(0);
    b.receive(&mut cell).unwrap();
    let mut replay = cell.clone();
    assert!(b.receive(&mut replay).is_err());
}

#[test]
fn bolt_channel_padding_is_hidden_by_ciphertext() {
    let (mut a, mut b) = pair(256);
    let mut cell = a.send_padding().unwrap();
    assert_eq!(cell.len(), 256 + BOLT_OVERHEAD);
    assert!(matches!(b.receive(&mut cell).unwrap(), Received::Padding));
}

#[test]
fn bolt_channels_with_different_keys_do_not_interoperate() {
    let mut a = BoltChannel::new([7u8; 32], [8u8; 32], 256, 1 << 20).unwrap();
    let mut b = BoltChannel::new([9u8; 32], [10u8; 32], 256, 1 << 20).unwrap();
    let mut cell = a.send(b"secret").unwrap().remove(0);
    assert!(b.receive(&mut cell).is_err());
}
