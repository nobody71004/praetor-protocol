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

use std::collections::{HashSet, VecDeque};

use aegis::aegis256::Aegis256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::util::{ct_eq, hkdf_sha256, hmac_sha256, random_array, u16be, u64be};
use crate::wire::{
    pack_cell_into_zero, unpack_cell_view, Assembler, Cell, Received, ReceivedRef,
    CELL_HEADER_BYTES, CELL_PAD, MAX_CELL_SIZE,
};

pub const NONCE_BYTES: usize = 16;
pub const SIV_BYTES: usize = 32;
pub const TAG_BYTES: usize = 32;
pub const OVERHEAD: usize = NONCE_BYTES + SIV_BYTES + TAG_BYTES;
pub const DETERMINISTIC_OVERHEAD: usize = SIV_BYTES + TAG_BYTES;

/// Per-cell wire overhead of the fixed-cell channel: the probabilistic
/// envelope's nonce, SIV and AEGIS-256 tag.
pub const CELL_OVERHEAD: usize = OVERHEAD;

/// AEGIS-256 limits plaintext and associated data to 2^61 - 1 bytes.
const MAX_BYTES: u64 = (1 << 61) - 1;
const LABEL_SALT: &[u8] = b"PRAETOR/1";
const LABEL_INFO: &[u8] = b"pmarine";
const LABEL_SIV: &[u8] = b"PMARINE/1/siv";
const LABEL_AEAD: &[u8] = b"PMARINE/1/aead";
const LABEL_CHANNEL: &[u8] = b"PRAETOR/PMARINE/1";

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

/// Bounded replay window over monotonically increasing 64-bit cell counters.
struct CounterWindow {
    capacity: usize,
    seen: HashSet<u64>,
    order: VecDeque<u64>,
}

impl CounterWindow {
    fn new(capacity: usize) -> Self {
        Self { capacity, seen: HashSet::new(), order: VecDeque::new() }
    }

    fn accept(&mut self, counter: u64) -> Result<()> {
        if !self.seen.insert(counter) {
            return Err(Error::Replay);
        }
        self.order.push_back(counter);
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        Ok(())
    }
}

/// A full-duplex fixed-cell channel using the PMARINE envelope per cell.
///
/// Each cell is `nonce || siv || AEGIS-256(cell) || tag`, where the 16-byte
/// nonce is an 8-byte per-channel prefix plus a 64-bit counter. The counter
/// both makes every AEGIS nonce distinct and drives the replay window. The
/// cell's AAD binds the profile label and the fixed cell size, so cells from a
/// channel with a different geometry do not authenticate.
pub struct PmarineChannel {
    cell_size: usize,
    payload_capacity: usize,
    send_key: PmarineKey,
    recv_key: PmarineKey,
    send_prefix: [u8; 8],
    send_counter: u64,
    next_msg_id: u64,
    replay: CounterWindow,
    assembler: Assembler,
    aad: Vec<u8>,
    aead_aad: Vec<u8>,
}

impl PmarineChannel {
    pub fn new(
        send_key: [u8; 32],
        recv_key: [u8; 32],
        cell_size: usize,
        max_message_bytes: usize,
    ) -> Result<Self> {
        if cell_size < CELL_HEADER_BYTES + 1 || cell_size > MAX_CELL_SIZE {
            return Err(Error::Range);
        }
        let mut aad = Vec::with_capacity(LABEL_CHANNEL.len() + 2);
        aad.extend_from_slice(LABEL_CHANNEL);
        aad.extend_from_slice(&u16be(cell_size as u16));
        let mut aead_aad = Vec::with_capacity(LABEL_AEAD.len() + aad.len());
        aead_aad.extend_from_slice(LABEL_AEAD);
        aead_aad.extend_from_slice(&aad);
        Ok(Self {
            cell_size,
            payload_capacity: cell_size - CELL_HEADER_BYTES,
            send_key: PmarineKey::new(&send_key)?,
            recv_key: PmarineKey::new(&recv_key)?,
            send_prefix: random_array::<8>(),
            send_counter: 0,
            next_msg_id: u64::from_be_bytes(random_array::<8>()),
            replay: CounterWindow::new(4096),
            assembler: Assembler::new(max_message_bytes, 1 << 16),
            aad,
            aead_aad,
        })
    }

    fn seal_cell_into(&mut self, cell: &Cell, out: &mut Vec<u8>) -> Result<()> {
        let base = out.len();
        out.resize(base + CELL_OVERHEAD + self.cell_size, 0);
        let mut nonce = [0u8; NONCE_BYTES];
        nonce[..8].copy_from_slice(&self.send_prefix);
        nonce[8..].copy_from_slice(&self.send_counter.to_be_bytes());
        out[base..base + NONCE_BYTES].copy_from_slice(&nonce);

        let siv_at = base + NONCE_BYTES;
        let body_at = siv_at + SIV_BYTES;
        let body_end = body_at + self.cell_size;
        let siv = {
            let body = &mut out[body_at..body_end];
            pack_cell_into_zero(cell, self.cell_size, body)?;
            self.send_key.siv(&nonce, &self.aad, body)
        };
        out[siv_at..body_at].copy_from_slice(&siv);
        let tag = {
            let body = &mut out[body_at..body_end];
            Aegis256::<TAG_BYTES>::new(&self.send_key.k_enc, &siv)
                .encrypt_in_place(body, &self.aead_aad)
        };
        out[body_end..body_end + TAG_BYTES].copy_from_slice(&tag);
        self.send_counter = self.send_counter.checked_add(1).ok_or(Error::Range)?;
        Ok(())
    }

    /// Fragment and seal one message into a caller-owned buffer.
    ///
    /// This is the zero-allocation path: `out` only grows to its high-water
    /// mark, so a tunnel can reuse one buffer for every packet.
    pub fn send_into(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let count = ((data.len() + self.payload_capacity - 1) / self.payload_capacity).max(1);
        if count > u16::MAX as usize {
            return Err(Error::Policy);
        }
        let msg_id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        for i in 0..count {
            let from = i * self.payload_capacity;
            let to = (from + self.payload_capacity).min(data.len());
            let cell = Cell::data(msg_id, i as u16, count as u16, &data[from..to]);
            self.seal_cell_into(&cell, out)?;
        }
        Ok(())
    }

    /// Convenience wrapper: one allocation per message, then one per cell.
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut flat = Vec::new();
        self.send_into(data, &mut flat)?;
        let cell_len = CELL_OVERHEAD + self.cell_size;
        Ok(flat.chunks(cell_len).map(|c| c.to_vec()).collect())
    }

    pub fn send_padding(&mut self) -> Result<Vec<u8>> {
        let msg_id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        let mut out = Vec::with_capacity(CELL_OVERHEAD + self.cell_size);
        self.seal_cell_into(&Cell::padding(msg_id), &mut out)?;
        Ok(out)
    }

    /// Authenticate, decrypt and decode one wire cell, borrowing the payload
    /// in place. The AEGIS tag is checked first; the SIV is then re-derived
    /// from the recovered plaintext as the independent commitment.
    pub fn receive_ref<'a>(&mut self, wire: &'a mut [u8]) -> Result<ReceivedRef<'a>> {
        if wire.len() != CELL_OVERHEAD + self.cell_size {
            return Err(Error::Truncated);
        }
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(&wire[..NONCE_BYTES]);
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&nonce[8..]);
        let counter = u64::from_be_bytes(counter_bytes);

        let siv_at = NONCE_BYTES;
        let body_at = siv_at + SIV_BYTES;
        let body_end = body_at + self.cell_size;
        let mut siv = [0u8; SIV_BYTES];
        siv.copy_from_slice(&wire[siv_at..body_at]);
        let mut tag = [0u8; TAG_BYTES];
        tag.copy_from_slice(&wire[body_end..]);

        if Aegis256::<TAG_BYTES>::new(&self.recv_key.k_enc, &siv)
            .decrypt_in_place(&mut wire[body_at..body_end], &tag, &self.aead_aad)
            .is_err()
        {
            wire.fill(0);
            return Err(Error::Auth);
        }
        let expected = self.recv_key.siv(&nonce, &self.aad, &wire[body_at..body_end]);
        if !ct_eq(&siv, &expected) {
            wire.fill(0);
            return Err(Error::Auth);
        }

        let view = unpack_cell_view(&wire[body_at..body_end], self.cell_size)?;
        self.replay.accept(counter)?;
        if view.kind == CELL_PAD {
            return Ok(ReceivedRef::Padding);
        }
        if view.frag_count == 1 {
            return Ok(ReceivedRef::Complete { msg_id: view.msg_id, data: view.payload });
        }
        let cell = Cell {
            kind: view.kind,
            flags: view.flags,
            frag_index: view.frag_index,
            frag_count: view.frag_count,
            msg_id: view.msg_id,
            payload: view.payload.to_vec(),
        };
        match self.assembler.push(&cell)? {
            None => Ok(ReceivedRef::Fragment { kind: view.kind, msg_id: view.msg_id }),
            Some((msg_id, data)) => Ok(ReceivedRef::Assembled { msg_id, data }),
        }
    }

    /// Authenticate and decode one wire cell into an owned payload.
    pub fn receive(&mut self, wire: &mut [u8]) -> Result<Received> {
        match self.receive_ref(wire)? {
            ReceivedRef::Padding => Ok(Received::Padding),
            ReceivedRef::Fragment { kind, msg_id } => Ok(Received::Fragment { kind, msg_id }),
            ReceivedRef::Complete { msg_id, data } => {
                Ok(Received::Complete { msg_id, data: data.to_vec() })
            }
            ReceivedRef::Assembled { msg_id, data } => Ok(Received::Complete { msg_id, data }),
        }
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
