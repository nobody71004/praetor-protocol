use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::util::{ct_eq, hkdf_sha256, hmac_sha256, read_u64, sha256, u64be};

pub const NONCE_BYTES: usize = 16;
pub const PREFIX_BYTES: usize = 16;
pub const AEAD_TAG_BYTES: usize = 16;
pub const TAG_BYTES: usize = 32;
pub const OVERHEAD: usize = NONCE_BYTES + PREFIX_BYTES + AEAD_TAG_BYTES + TAG_BYTES;
pub const DETERMINISTIC_OVERHEAD: usize = PREFIX_BYTES + AEAD_TAG_BYTES + TAG_BYTES;

const LABEL_SALT: &[u8] = b"VANTA/1";
const LABEL_INFO: &[u8] = b"vseal";
const LABEL_SIV: &[u8] = b"VSEAL/1/siv";
const LABEL_AEAD: &[u8] = b"VSEAL/1/aead";
const LABEL_TAG: &[u8] = b"VSEAL/1/tag";
const LABEL_AAD: &[u8] = b"VSEAL/1/aad";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SealKey {
    k_siv: [u8; 32],
    k_enc: [u8; 32],
    k_com: [u8; 32],
}

impl SealKey {
    pub fn new(master: &[u8]) -> Result<Self> {
        if master.len() != 32 {
            return Err(Error::Key);
        }
        let mut prk = [0u8; 96];
        hkdf_sha256(master, LABEL_SALT, LABEL_INFO, &mut prk);
        let mut k_siv = [0u8; 32];
        let mut k_enc = [0u8; 32];
        let mut k_com = [0u8; 32];
        k_siv.copy_from_slice(&prk[0..32]);
        k_enc.copy_from_slice(&prk[32..64]);
        k_com.copy_from_slice(&prk[64..96]);
        prk.zeroize();
        Ok(Self { k_siv, k_enc, k_com })
    }

    fn prefix(&self, nonce: &[u8], aad: &[u8], pt: &[u8]) -> [u8; PREFIX_BYTES] {
        let alen = u64be(aad.len() as u64);
        let plen = u64be(pt.len() as u64);
        let mac = hmac_sha256(
            &self.k_siv,
            &[LABEL_SIV, nonce, &alen, aad, &plen, pt],
        );
        let mut out = [0u8; PREFIX_BYTES];
        out.copy_from_slice(&mac[..PREFIX_BYTES]);
        out
    }

    fn tag(&self, nonce: &[u8], prefix: &[u8], ct: &[u8], aad: &[u8]) -> [u8; TAG_BYTES] {
        let aad_hash = sha256(&[LABEL_AAD, aad]);
        hmac_sha256(&self.k_com, &[LABEL_TAG, nonce, prefix, ct, &aad_hash])
    }

    /// Seal with a caller-supplied nonce; `None` selects deterministic mode.
    pub fn seal(&self, pt: &[u8], aad: &[u8], nonce: Option<[u8; NONCE_BYTES]>) -> Result<Vec<u8>> {
        let nonce_bytes: &[u8] = nonce.as_ref().map(|n| n.as_slice()).unwrap_or(&[]);
        let prefix = self.prefix(nonce_bytes, aad, pt);

        let cipher = ChaCha20Poly1305::new_from_slice(&self.k_enc).expect("32-byte key");
        let mut inner_aad = Vec::with_capacity(LABEL_AEAD.len() + aad.len());
        inner_aad.extend_from_slice(LABEL_AEAD);
        inner_aad.extend_from_slice(aad);
        let ct = cipher
            .encrypt(Nonce::from_slice(&prefix[..12]), Payload { msg: pt, aad: &inner_aad })
            .map_err(|_| Error::Auth)?;

        let tag = self.tag(nonce_bytes, &prefix, &ct, aad);
        let mut out = Vec::with_capacity(nonce_bytes.len() + PREFIX_BYTES + ct.len() + TAG_BYTES);
        out.extend_from_slice(nonce_bytes);
        out.extend_from_slice(&prefix);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    pub fn seal_random(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.seal(pt, aad, Some(crate::util::random_array::<NONCE_BYTES>()))
    }

    pub fn open(&self, envelope: &[u8], aad: &[u8], deterministic: bool) -> Result<Vec<u8>> {
        let head = if deterministic { 0 } else { NONCE_BYTES };
        let min = head + PREFIX_BYTES + AEAD_TAG_BYTES + TAG_BYTES;
        if envelope.len() < min {
            return Err(Error::Truncated);
        }
        let nonce = &envelope[..head];
        let prefix = &envelope[head..head + PREFIX_BYTES];
        let ct = &envelope[head + PREFIX_BYTES..envelope.len() - TAG_BYTES];
        let tag = &envelope[envelope.len() - TAG_BYTES..];

        let expected = self.tag(nonce, prefix, ct, aad);
        if !ct_eq(tag, &expected) {
            return Err(Error::Auth);
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.k_enc).expect("32-byte key");
        let mut inner_aad = Vec::with_capacity(LABEL_AEAD.len() + aad.len());
        inner_aad.extend_from_slice(LABEL_AEAD);
        inner_aad.extend_from_slice(aad);
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&prefix[..12]),
                Payload { msg: ct, aad: &inner_aad },
            )
            .map_err(|_| Error::Auth)?;

        let reproved = self.prefix(nonce, aad, &pt);
        if !ct_eq(prefix, &reproved) {
            return Err(Error::Auth);
        }
        Ok(pt)
    }
}

/// Convenience for one-off sealing (key expansion each call).
pub fn seal(master: &[u8], pt: &[u8], aad: &[u8], nonce: Option<[u8; NONCE_BYTES]>) -> Result<Vec<u8>> {
    SealKey::new(master)?.seal(pt, aad, nonce)
}

pub fn open(master: &[u8], envelope: &[u8], aad: &[u8], deterministic: bool) -> Result<Vec<u8>> {
    SealKey::new(master)?.open(envelope, aad, deterministic)
}

/// Parse the SIV prefix for tests and tooling.
pub fn envelope_parts(envelope: &[u8], deterministic: bool) -> Result<(&[u8], &[u8], &[u8], &[u8])> {
    let head = if deterministic { 0 } else { NONCE_BYTES };
    if envelope.len() < head + PREFIX_BYTES + AEAD_TAG_BYTES + TAG_BYTES {
        return Err(Error::Truncated);
    }
    let split = envelope.len() - TAG_BYTES;
    Ok((
        &envelope[..head],
        &envelope[head..head + PREFIX_BYTES],
        &envelope[head + PREFIX_BYTES..split],
        &envelope[split..],
    ))
}

#[allow(dead_code)]
fn _unused(buf: &[u8]) -> u64 {
    read_u64(buf, 0)
}
