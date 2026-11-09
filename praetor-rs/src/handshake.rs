//! PRAETOR-HS/1 — one round-trip hybrid handshake.
//!
//! C -> S: ct1 (1120) || ephC_pk (1216) || nonceC (32)
//! S -> C: ct2 (1120) || nonceS (32) || confirmS (32)
//! C -> S: confirmC (32)

use crate::error::{Error, Result};
use crate::util::{ct_eq, hkdf_sha256, hmac_sha256, random_array, sha256, sha3_256};
use crate::xwing::{self, XWING_CT_BYTES, XWING_PK_BYTES};

const LABEL_SS: &[u8] = b"PRAETOR-HS/1";
const LABEL_SESSION: &[u8] = b"PRAETOR/1/session";
const LABEL_CONFIRM_S: &[u8] = b"PRAETOR/1/server-confirm";
const LABEL_CONFIRM_C: &[u8] = b"PRAETOR/1/client-confirm";
const LABEL_SID: &[u8] = b"PRAETOR/1/session-id";

pub const HS_C1_BYTES: usize = XWING_CT_BYTES + XWING_PK_BYTES + 32;
pub const HS_S1_BYTES: usize = XWING_CT_BYTES + 32 + 32;
pub const HS_CONFIRM_BYTES: usize = 32;

pub struct ClientState {
    eph_secret: Vec<u8>,
    ss1: [u8; 32],
    ct1: Vec<u8>,
    eph_public: Vec<u8>,
    nonce_c: [u8; 32],
    first: Vec<u8>,
    pub transcript_hash: [u8; 32],
    pub session_id: [u8; 32],
    confirm_key: [u8; 32],
    c2s: [u8; 32],
    s2c: [u8; 32],
    phase: u8,
}

pub struct ServerState {
    pub transcript_hash: [u8; 32],
    pub session_id: [u8; 32],
    confirm_key: [u8; 32],
    c2s: [u8; 32],
    s2c: [u8; 32],
    phase: u8,
}

pub struct Session {
    pub role: Role,
    pub send_chain: [u8; 32],
    pub recv_chain: [u8; 32],
    pub session_id: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Client,
    Server,
}

fn derive(
    ss1: &[u8],
    ss2: &[u8],
    ct1: &[u8],
    ct2: &[u8],
    eph_c: &[u8],
    nonce_c: &[u8],
    nonce_s: &[u8],
    transcript: &[u8],
) -> Result<([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32])> {
    let transcript_hash = sha256(&[transcript]);
    let ss = sha3_256(&[LABEL_SS, ss1, ss2, ct1, ct2, eph_c, &transcript_hash]);
    let salt = sha256(&[nonce_c, nonce_s]);
    let mut keys = [0u8; 96];
    hkdf_sha256(&ss, &salt, LABEL_SESSION, &mut keys);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    let mut confirm = [0u8; 32];
    c2s.copy_from_slice(&keys[0..32]);
    s2c.copy_from_slice(&keys[32..64]);
    confirm.copy_from_slice(&keys[64..96]);
    let session_id = sha256(&[LABEL_SID, &ss, &transcript_hash]);
    Ok((c2s, s2c, confirm, transcript_hash, session_id))
}

pub fn client_init(server_pk: &[u8]) -> Result<(Vec<u8>, ClientState)> {
    let (eph_pk, eph_sk) = xwing::keygen();
    let (ct1, ss1) = xwing::encapsulate(server_pk)?;
    let nonce_c: [u8; 32] = random_array();
    let mut first = Vec::with_capacity(HS_C1_BYTES);
    first.extend_from_slice(&ct1);
    first.extend_from_slice(&eph_pk);
    first.extend_from_slice(&nonce_c);
    if first.len() != HS_C1_BYTES {
        return Err(Error::Malformed);
    }
    Ok((
        first.clone(),
        ClientState {
            eph_secret: eph_sk,
            ss1,
            ct1,
            eph_public: eph_pk,
            nonce_c,
            first,
            transcript_hash: [0u8; 32],
            session_id: [0u8; 32],
            confirm_key: [0u8; 32],
            c2s: [0u8; 32],
            s2c: [0u8; 32],
            phase: 0,
        },
    ))
}

pub fn server_respond(server_sk: &[u8], message: &[u8]) -> Result<(Vec<u8>, ServerState)> {
    let server_pk = xwing::public_from_secret(server_sk)?;
    server_respond_with_pk(&server_pk, server_sk, message)
}

/// Like [`server_respond`], but reuses the server's already-computed public
/// key instead of deriving it from the secret key.
pub fn server_respond_with_pk(
    server_pk: &[u8],
    server_sk: &[u8],
    message: &[u8],
) -> Result<(Vec<u8>, ServerState)> {
    if server_pk.len() != XWING_PK_BYTES {
        return Err(Error::Key);
    }
    if message.len() != HS_C1_BYTES {
        return Err(Error::Malformed);
    }
    let ct1 = &message[..XWING_CT_BYTES];
    let eph_c = &message[XWING_CT_BYTES..XWING_CT_BYTES + XWING_PK_BYTES];
    let nonce_c = &message[XWING_CT_BYTES + XWING_PK_BYTES..];

    let mut server_pk_x = [0u8; 32];
    server_pk_x.copy_from_slice(&server_pk[xwing::XWING_X25519_PK_OFFSET..][..32]);
    let ss1 = xwing::decapsulate_with_pk(ct1, server_sk, &server_pk_x)?;
    let (ct2, ss2) = xwing::encapsulate(eph_c)?;
    let nonce_s: [u8; 32] = random_array();

    let mut transcript = Vec::with_capacity(message.len() + ct2.len() + 32);
    transcript.extend_from_slice(message);
    transcript.extend_from_slice(&ct2);
    transcript.extend_from_slice(&nonce_s);

    let (c2s, s2c, confirm, transcript_hash, session_id) =
        derive(&ss1, &ss2, ct1, &ct2, eph_c, nonce_c, &nonce_s, &transcript)?;
    let confirm_s = hmac_sha256(&confirm, &[LABEL_CONFIRM_S, &transcript_hash]);

    let mut reply = Vec::with_capacity(HS_S1_BYTES);
    reply.extend_from_slice(&ct2);
    reply.extend_from_slice(&nonce_s);
    reply.extend_from_slice(&confirm_s);
    if reply.len() != HS_S1_BYTES {
        return Err(Error::Malformed);
    }
    Ok((
        reply,
        ServerState {
            transcript_hash,
            session_id,
            confirm_key: confirm,
            c2s,
            s2c,
            phase: 1,
        },
    ))
}

pub fn client_finish(state: &mut ClientState, reply: &[u8]) -> Result<([u8; 32], Session)> {
    if state.phase != 0 {
        return Err(Error::Policy);
    }
    if reply.len() != HS_S1_BYTES {
        return Err(Error::Malformed);
    }
    let ct2 = &reply[..XWING_CT_BYTES];
    let nonce_s = &reply[XWING_CT_BYTES..XWING_CT_BYTES + 32];
    let confirm_s = &reply[XWING_CT_BYTES + 32..];

    let mut client_pk_x = [0u8; 32];
    client_pk_x.copy_from_slice(
        &state.eph_public[xwing::XWING_X25519_PK_OFFSET..][..32],
    );
    let ss2 = xwing::decapsulate_with_pk(ct2, &state.eph_secret, &client_pk_x)?;
    let mut transcript = Vec::with_capacity(state.first.len() + ct2.len() + 32);
    transcript.extend_from_slice(&state.first);
    transcript.extend_from_slice(ct2);
    transcript.extend_from_slice(nonce_s);

    let (c2s, s2c, confirm, transcript_hash, session_id) = derive(
        &state.ss1,
        &ss2,
        &state.ct1,
        ct2,
        &state.eph_public,
        &state.nonce_c,
        nonce_s,
        &transcript,
    )?;
    let expect = hmac_sha256(&confirm, &[LABEL_CONFIRM_S, &transcript_hash]);
    if !ct_eq(confirm_s, &expect) {
        return Err(Error::Auth);
    }
    let confirm_c = hmac_sha256(&confirm, &[LABEL_CONFIRM_C, &transcript_hash]);
    state.phase = 2;
    state.transcript_hash = transcript_hash;
    state.session_id = session_id;
    state.confirm_key = confirm;
    state.c2s = c2s;
    state.s2c = s2c;
    Ok((
        confirm_c,
        Session { role: Role::Client, send_chain: c2s, recv_chain: s2c, session_id },
    ))
}

pub fn server_finish(state: &mut ServerState, confirm: &[u8]) -> Result<Session> {
    if state.phase != 1 {
        return Err(Error::Policy);
    }
    if confirm.len() != HS_CONFIRM_BYTES {
        return Err(Error::Malformed);
    }
    let expect = hmac_sha256(&state.confirm_key, &[LABEL_CONFIRM_C, &state.transcript_hash]);
    if !ct_eq(confirm, &expect) {
        return Err(Error::Auth);
    }
    state.phase = 2;
    Ok(Session {
        role: Role::Server,
        send_chain: state.s2c,
        recv_chain: state.c2s,
        session_id: state.session_id,
    })
}
