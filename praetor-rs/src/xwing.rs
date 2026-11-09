//! PRAETOR-KEM/1 — X-Wing structure over X25519 + ML-KEM-768.
//!
//! `pk = mlkem_pk (1184) || x25519_pk (32)`
//! `sk = mlkem_sk (2400) || x25519_sk (32)`
//! `ct = mlkem_ct (1088) || x25519_ephemeral_pk (32)`
//! `ss = SHA3-256(label || ss_m || ss_x || ct_x || pk_x)`

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, Result};
use crate::util::sha3_256;

pub const XWING_PK_BYTES: usize = 1184 + 32;
pub const XWING_SK_BYTES: usize = 2400 + 32;
pub const XWING_CT_BYTES: usize = 1088 + 32;
pub const XWING_SS_BYTES: usize = 32;
pub const LABEL: &[u8] = b"PRAETOR-KEM/1 X-Wing";

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;
type Ct = ml_kem::Ciphertext<MlKem768>;

fn combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> [u8; 32] {
    sha3_256(&[LABEL, ss_m, ss_x, ct_x, pk_x])
}

/// Returns `(public_key, secret_key)`.
pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    let mut pk = ek.as_bytes().to_vec();
    let mut sk = dk.as_bytes().to_vec();
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
    // The ML-KEM public key is embedded in the decapsulation key at the FIPS
    // 203 layout offset, but the safer path is to require the pair at keygen.
    let dk_arr = Encoded::<Dk>::try_from(&sk[..2400]).map_err(|_| Error::Key)?;
    let dk = Dk::from_bytes(&dk_arr);
    let ml_pk = dk.encapsulation_key().as_bytes();
    let mut out = Vec::with_capacity(XWING_PK_BYTES);
    out.extend_from_slice(&ml_pk);
    out.extend_from_slice(PublicKey::from(&secret).as_bytes());
    Ok(out)
}

pub fn encapsulate(pk: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    if pk.len() != XWING_PK_BYTES {
        return Err(Error::Key);
    }
    let ml_pk = Encoded::<Ek>::try_from(&pk[..1184]).map_err(|_| Error::Key)?;
    let ek = Ek::from_bytes(&ml_pk);
    let mut pk_x = [0u8; 32];
    pk_x.copy_from_slice(&pk[1184..]);
    if pk_x == [0u8; 32] {
        return Err(Error::Key);
    }

    let (ct_m, ss_m) = ek.encapsulate(&mut OsRng).map_err(|_| Error::Malformed)?;
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
    let ct_m = Ct::try_from(&ct[..1088]).map_err(|_| Error::Malformed)?;
    let dk_arr = Encoded::<Dk>::try_from(&sk[..2400]).map_err(|_| Error::Key)?;
    let dk = Dk::from_bytes(&dk_arr);

    let mut sk_x = [0u8; 32];
    sk_x.copy_from_slice(&sk[2400..]);
    let secret = StaticSecret::from(sk_x);
    let mut ct_x = [0u8; 32];
    ct_x.copy_from_slice(&ct[1088..]);
    if ct_x == [0u8; 32] {
        return Err(Error::Auth);
    }
    let ss_x = secret.diffie_hellman(&PublicKey::from(ct_x));
    if ss_x.as_bytes() == &[0u8; 32] {
        return Err(Error::Auth);
    }
    // ML-KEM decapsulation is infallible by design (implicit rejection), so a
    // bad ciphertext yields a pseudorandom secret and the handshake
    // confirmation is what rejects it.
    let ss_m = dk.decapsulate(&ct_m).map_err(|_| Error::Auth)?;
    let pk_x = PublicKey::from(&secret);
    Ok(combiner(ss_m.as_slice(), ss_x.as_bytes(), &ct_x, pk_x.as_bytes()))
}

