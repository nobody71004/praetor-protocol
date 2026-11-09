//! PRAETOR/PMARINE — PSEAL/2, an AEGIS-256 envelope.
//!
//! PMARINE keeps PSEAL's SIV construction and envelope shape, but replaces
//! ChaCha20-Poly1305 plus the separate HMAC commitment tag with AEGIS-256
//! (RFC 10032) and a full 256-bit SIV. The SIV is the AEGIS nonce, so a reused
//! outer nonce still gives distinct AEGIS nonces for distinct plaintexts.
//!
//! After authenticated decryption the SIV is re-derived from the plaintext and
//! compared. That check is the independent commitment: it does not rely on
//! AEGIS's built-in key commitment, which is not full when an attacker can
//! choose the associated data (IACR ePrint 2023/1495; RFC 10032 §9.1.2).
//!
//! This is a profile/composition, not a new primitive. It has not been audited.

use aegis::aegis256::Aegis256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::util::{ct_eq, hkdf_sha256, hmac_sha256, u64be};

pub const NONCE_BYTES: usize = 16;
pub const SIV_BYTES: usize = 32;
pub const TAG_BYTES: usize = 32;
pub const OVERHEAD: usize = NONCE_BYTES + SIV_BYTES + TAG_BYTES;
pub const DETERMINISTIC_OVERHEAD: usize = SIV_BYTES + TAG_BYTES;

/// AEGIS-256 limits plaintext and associated data to 2^61 - 1 bytes.
const MAX_BYTES: u64 = (1 << 61) - 1;
const LABEL_SALT: &[u8] = b"PRAETOR/1";
const LABEL_INFO: &[u8] = b"pmarine";
const LABEL_SIV: &[u8] = b"PMARINE/1/siv";
const LABEL_AEAD: &[u8] = b"PMARINE/1/aead";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PmarineKey {
    k_siv: [u8; 32],
    k_enc: [u8; 32],
}

impl PmarineKey {
    pub fn new(master: &[u8]) -> Result<Self> {
        if master.len() != 32 {
            return Err(Error::Key);
        }
        let mut prk = [0u8; 64];
        hkdf_sha256(master, LABEL_SALT, LABEL_INFO, &mut prk);
        let mut k_siv = [0u8; 32];
        let mut k_enc = [0u8; 32];
        k_siv.copy_from_slice(&prk[..32]);
        k_enc.copy_from_slice(&prk[32..]);
        prk.zeroize();
        Ok(Self { k_siv, k_enc })
    }

    fn siv(&self, nonce: &[u8], aad: &[u8], pt: &[u8]) -> [u8; SIV_BYTES] {
        let alen = u64be(aad.len() as u64);
        let plen = u64be(pt.len() as u64);
        hmac_sha256(&self.k_siv, &[LABEL_SIV, nonce, &alen, aad, &plen, pt])
    }

    fn aead_aad(aad: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(LABEL_AEAD.len() + aad.len());
        out.extend_from_slice(LABEL_AEAD);
        out.extend_from_slice(aad);
        out
    }

    /// Seal with a caller-supplied nonce; `None` selects deterministic mode.
    pub fn seal(
        &self,
        pt: &[u8],
        aad: &[u8],
        nonce: Option<[u8; NONCE_BYTES]>,
    ) -> Result<Vec<u8>> {
        check_len(pt.len(), aad.len())?;
        let nonce_bytes: &[u8] = nonce.as_ref().map(|n| n.as_slice()).unwrap_or(&[]);
        let siv = self.siv(nonce_bytes, aad, pt);

        let mut out =
            Vec::with_capacity(nonce_bytes.len() + SIV_BYTES + pt.len() + TAG_BYTES);
        out.extend_from_slice(nonce_bytes);
        out.extend_from_slice(&siv);
        let body_start = out.len();
        out.extend_from_slice(pt);
        let tag = Aegis256::<TAG_BYTES>::new(&self.k_enc, &siv)
            .encrypt_in_place(&mut out[body_start..], &Self::aead_aad(aad));
        out.extend_from_slice(&tag);
        Ok(out)
    }

    pub fn seal_random(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.seal(pt, aad, Some(crate::util::random_array::<NONCE_BYTES>()))
    }

    pub fn open(&self, envelope: &[u8], aad: &[u8], deterministic: bool) -> Result<Vec<u8>> {
        let head = if deterministic { 0 } else { NONCE_BYTES };
        let min = head + SIV_BYTES + TAG_BYTES;
        if envelope.len() < min {
            return Err(Error::Truncated);
        }
        let nonce = &envelope[..head];
        let siv_end = head + SIV_BYTES;
        let tag_start = envelope.len() - TAG_BYTES;
        let ct = &envelope[siv_end..tag_start];
        check_len(ct.len(), aad.len())?;

        let mut siv = [0u8; SIV_BYTES];
        siv.copy_from_slice(&envelope[head..siv_end]);
        let mut tag = [0u8; TAG_BYTES];
        tag.copy_from_slice(&envelope[tag_start..]);

        let mut pt = ct.to_vec();
        if Aegis256::<TAG_BYTES>::new(&self.k_enc, &siv)
            .decrypt_in_place(&mut pt, &tag, &Self::aead_aad(aad))
            .is_err()
        {
            pt.zeroize();
            return Err(Error::Auth);
        }

        let expected = self.siv(nonce, aad, &pt);
        if !ct_eq(&siv, &expected) {
            pt.zeroize();
            return Err(Error::Auth);
        }
        Ok(pt)
    }
}

fn check_len(pt_len: usize, aad_len: usize) -> Result<()> {
    if pt_len as u64 > MAX_BYTES || aad_len as u64 > MAX_BYTES {
        return Err(Error::Range);
    }
    Ok(())
}

/// Convenience for one-off sealing (key expansion each call).
pub fn seal(
    master: &[u8],
    pt: &[u8],
    aad: &[u8],
    nonce: Option<[u8; NONCE_BYTES]>,
) -> Result<Vec<u8>> {
    PmarineKey::new(master)?.seal(pt, aad, nonce)
}

pub fn open(master: &[u8], envelope: &[u8], aad: &[u8], deterministic: bool) -> Result<Vec<u8>> {
    PmarineKey::new(master)?.open(envelope, aad, deterministic)
}

/// Parse the envelope for tests and tooling.
pub fn envelope_parts(
    envelope: &[u8],
    deterministic: bool,
) -> Result<(&[u8], &[u8], &[u8], &[u8])> {
    let head = if deterministic { 0 } else { NONCE_BYTES };
    if envelope.len() < head + SIV_BYTES + TAG_BYTES {
        return Err(Error::Truncated);
    }
    let split = envelope.len() - TAG_BYTES;
    Ok((
        &envelope[..head],
        &envelope[head..head + SIV_BYTES],
        &envelope[head + SIV_BYTES..split],
        &envelope[split..],
    ))
}
