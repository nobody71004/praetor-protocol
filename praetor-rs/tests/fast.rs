use praetor::fast::FastChannel;
use praetor::wire::Received;

fn pair(cell_size: usize) -> (FastChannel, FastChannel) {
    (
        FastChannel::new([1u8; 32], [2u8; 32], cell_size, 64 << 20).unwrap(),
        FastChannel::new([2u8; 32], [1u8; 32], cell_size, 64 << 20).unwrap(),
    )
}

#[test]
fn fast_channel_roundtrip_and_fragmentation() {
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
fn fast_channel_rejects_tamper() {
    let (mut a, mut b) = pair(256);
    let mut cell = a.send(b"tamper").unwrap().remove(0);
    let last = cell.len() - 1;
    cell[last] ^= 1;
    assert!(b.receive(&mut cell).is_err());
}

#[test]
fn fast_channel_rejects_replay() {
    let (mut a, mut b) = pair(256);
    let mut cell = a.send(b"once").unwrap().remove(0);
    b.receive(&mut cell).unwrap();
    let mut replay = cell.clone();
    assert!(b.receive(&mut replay).is_err());
}

#[test]
fn fast_channel_padding_is_hidden_by_ciphertext() {
    let (mut a, mut b) = pair(256);
    let mut cell = a.send_padding().unwrap();
    assert_eq!(cell.len(), 256 + 12 + 16);
    assert!(matches!(b.receive(&mut cell).unwrap(), Received::Padding));
}
