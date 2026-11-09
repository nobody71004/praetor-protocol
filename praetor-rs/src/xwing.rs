//! PRAETOR-KEM/1 — X-Wing structure over X25519 + ML-KEM-768.
//!
//! `pk = mlkem_pk (1184) || x25519_pk (32)`
//! `sk = mlkem_sk (2400) || x25519_sk (32)`
//! `ct = mlkem_ct (1088) || x25519_ephemeral_pk (32)`
//! `ss = SHA3-256(label || ss_m || ss_x || ct_x || pk_x)`

use libcrux_ml_kem::mlkem768::{
    self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey,
};
use libcrux_ml_kem::{ENCAPS_SEED_SIZE, KEY_GENERATION_SEED_SIZE};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, Result};
use crate::util::{random_array, sha3_256};

pub const XWING_PK_BYTES: usize = 1184 + 32;
pub const XWING_SK_BYTES: usize = 2400 + 32;
pub const XWING_CT_BYTES: usize = 1088 + 32;
pub const XWING_SS_BYTES: usize = 32;
pub const XWING_X25519_PK_OFFSET: usize = 1184;
pub const XWING_X25519_SK_OFFSET: usize = 2400;
pub const LABEL: &[u8] = b"PRAETOR-KEM/1 X-Wing";

const MLKEM_PK_BYTES: usize = 1184;
const MLKEM_SK_BYTES: usize = 2400;
const MLKEM_CT_BYTES: usize = 1088;
// FIPS 203 secret-key layout: dk = dk_pke (1152) || ek (1184) || H(ek) || z.
const MLKEM_PK_OFFSET_IN_SK: usize = 1152;

fn combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> [u8; 32] {
    sha3_256(&[LABEL, ss_m, ss_x, ct_x, pk_x])
}

/// Returns `(public_key, secret_key)`.
pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let seed: [u8; KEY_GENERATION_SEED_SIZE] = random_array();
    let kp = mlkem768::generate_key_pair(seed);
    let mut pk = kp.pk().to_vec();
    let mut sk = kp.sk().to_vec();
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    pk.extend_from_slice(public.as_bytes());
    sk.extend_from_slice(secret.as_bytes());
    (pk, sk)
}

pub fn public_from_secret(sk: &[u8]) -> Result<Vec<u8>> {
    if sk.len() != XWING_SK_BYTES {
        return Err(Error::Key);
    }
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&sk[2400..]);
    let secret = StaticSecret::from(secret_bytes);
    let mut out = Vec::with_capacity(XWING_PK_BYTES);
    out.extend_from_slice(&sk[MLKEM_PK_OFFSET_IN_SK..MLKEM_PK_OFFSET_IN_SK + MLKEM_PK_BYTES]);
    out.extend_from_slice(PublicKey::from(&secret).as_bytes());
    Ok(out)
}

pub fn encapsulate(pk: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    if pk.len() != XWING_PK_BYTES {
        return Err(Error::Key);
    }
    let ml_pk = MlKem768PublicKey::try_from(&pk[..MLKEM_PK_BYTES]).map_err(|_| Error::Key)?;
    let mut pk_x = [0u8; 32];
    pk_x.copy_from_slice(&pk[1184..]);
    if pk_x == [0u8; 32] {
        return Err(Error::Key);
    }

    let seed: [u8; ENCAPS_SEED_SIZE] = random_array();
    let (ct_m, ss_m) = mlkem768::encapsulate(&ml_pk, seed);
    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_public = PublicKey::from(&eph_secret);
    let ct_x = eph_public.as_bytes();
    let ss_x = eph_secret.diffie_hellman(&PublicKey::from(pk_x));
    if ss_x.as_bytes() == &[0u8; 32] {
        return Err(Error::Auth);
    }

    let ss = combiner(ss_m.as_slice(), ss_x.as_bytes(), ct_x, &pk_x);
    let mut ct = Vec::with_capacity(XWING_CT_BYTES);
    ct.extend_from_slice(ct_m.as_slice());
    ct.extend_from_slice(ct_x);
    Ok((ct, ss))
}

pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Result<[u8; 32]> {
    if ct.len() != XWING_CT_BYTES || sk.len() != XWING_SK_BYTES {
        return Err(Error::Malformed);
    }
    let mut sk_x = [0u8; 32];
    sk_x.copy_from_slice(&sk[XWING_X25519_SK_OFFSET..]);
    let secret = StaticSecret::from(sk_x);
    let pk_x = PublicKey::from(&secret);
    decapsulate_with_pk(ct, sk, pk_x.as_bytes())
}

/// Like [`decapsulate`], but reuses the receiver's already-computed X25519
/// public key instead of deriving it from the secret key.
pub fn decapsulate_with_pk(ct: &[u8], sk: &[u8], pk_x: &[u8; 32]) -> Result<[u8; 32]> {
    if ct.len() != XWING_CT_BYTES || sk.len() != XWING_SK_BYTES {
        return Err(Error::Malformed);
    }
    let ct_m = MlKem768Ciphertext::try_from(&ct[..MLKEM_CT_BYTES])
        .map_err(|_| Error::Malformed)?;
    let dk = MlKem768PrivateKey::try_from(&sk[..MLKEM_SK_BYTES]).map_err(|_| Error::Key)?;

    let mut ct_x = [0u8; 32];
    ct_x.copy_from_slice(&ct[MLKEM_CT_BYTES..]);
    if ct_x == [0u8; 32] {
        return Err(Error::Auth);
    }
    let mut sk_x = [0u8; 32];
    sk_x.copy_from_slice(&sk[XWING_X25519_SK_OFFSET..]);
    let secret = StaticSecret::from(sk_x);
    let ss_x = secret.diffie_hellman(&PublicKey::from(ct_x));
    if ss_x.as_bytes() == &[0u8; 32] {
        return Err(Error::Auth);
    }
    // ML-KEM decapsulation is infallible by design (implicit rejection), so a
    // bad ciphertext yields a pseudorandom secret and the handshake
    // confirmation is what rejects it.
    let ss_m = mlkem768::decapsulate(&dk, &ct_m);
    Ok(combiner(ss_m.as_slice(), ss_x.as_bytes(), &ct_x, pk_x))
}
