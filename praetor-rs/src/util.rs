use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub type HmacSha256 = Hmac<Sha256>;

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    use sha3::Digest as _;
    let mut h = sha3::Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("HKDF output length is bounded");
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).expect("operating system RNG unavailable");
    out
}

pub fn random_vec(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    getrandom::getrandom(&mut out).expect("operating system RNG unavailable");
    out
}

pub fn u16be(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}

pub fn u32be(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

pub fn u64be(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

pub fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

pub fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

pub fn wipe(buf: &mut [u8]) {
    use zeroize::Zeroize;
    buf.zeroize();
}
