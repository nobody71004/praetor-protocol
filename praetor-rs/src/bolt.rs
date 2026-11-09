//! PRAETOR/BOLT — the fastest opt-in transport profile.
//!
//! BOLT keeps PRAETOR's fixed cells and replaces the per-cell AEAD with
//! AEGIS-128L. AEGIS is an ISO/IEC 29192-8 authenticated cipher built for
//! AES-NI: its eight-block state exposes far more instruction-level
//! parallelism than GCM's counter chain, which is why the `aegis` backend
//! measured several times ring's AES-256-GCM throughput on this machine.
//!
//! BOLT is **not** the default and it is weaker than PSEAL:
//!
//! * no SIV / nonce-misuse resistance;
//! * a 128-bit key (AEGIS-128L) instead of 256-bit;
//! * no per-cell commitment tag, though AEGIS-128L is itself key-committing;
//! * a stateful 64-bit counter that must never repeat under one key.
//!
//! It improves on PRAETOR/FAST in two ways: it is faster, and the 64-bit
//! counter removes FAST's 2^32-cell key lifetime. It is Rust-only.

use std::collections::{HashSet, VecDeque};

use aegis::aegis128l::Aegis128L;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::util::{random_array, u16be};
use crate::wire::{
    pack_cell_into_zero, unpack_cell_view, Assembler, Cell, Received, ReceivedRef,
    CELL_HEADER_BYTES, CELL_PAD, MAX_CELL_SIZE,
};

pub const BOLT_KEY_BYTES: usize = 16;
pub const BOLT_NONCE_BYTES: usize = 16;
pub const BOLT_TAG_BYTES: usize = 16;
pub const BOLT_OVERHEAD: usize = BOLT_NONCE_BYTES + BOLT_TAG_BYTES;
const LABEL: &[u8] = b"PRAETOR/BOLT/1";
const KEY_INFO: &[u8] = b"PRAETOR/BOLT/1/aegis128l";

/// Derive the 128-bit AEGIS key from the channel's 256-bit key material.
fn derive_key(key: &[u8; 32]) -> Result<[u8; BOLT_KEY_BYTES]> {
    let hk = Hkdf::<Sha256>::new(Some(LABEL), key);
    let mut out = [0u8; BOLT_KEY_BYTES];
    hk.expand(KEY_INFO, &mut out).map_err(|_| Error::Key)?;
    Ok(out)
}

/// Bounded replay window over monotonically increasing 64-bit counters.
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

/// A full-duplex fixed-cell channel using one AEGIS-128L pass per cell.
pub struct BoltChannel {
    cell_size: usize,
    payload_capacity: usize,
    send_key: [u8; BOLT_KEY_BYTES],
    recv_key: [u8; BOLT_KEY_BYTES],
    send_prefix: [u8; 8],
    send_counter: u64,
    next_msg_id: u64,
    replay: CounterWindow,
    assembler: Assembler,
    aad: Vec<u8>,
}

impl BoltChannel {
    pub fn new(
        send_key: [u8; 32],
        recv_key: [u8; 32],
        cell_size: usize,
        max_message_bytes: usize,
    ) -> Result<Self> {
        if cell_size < CELL_HEADER_BYTES + 1 || cell_size > MAX_CELL_SIZE {
            return Err(Error::Range);
        }
        let mut aad = Vec::with_capacity(LABEL.len() + 2);
        aad.extend_from_slice(LABEL);
        aad.extend_from_slice(&u16be(cell_size as u16));
        Ok(Self {
            cell_size,
            payload_capacity: cell_size - CELL_HEADER_BYTES,
            send_key: derive_key(&send_key)?,
            recv_key: derive_key(&recv_key)?,
            send_prefix: random_array::<8>(),
            send_counter: 0,
            next_msg_id: u64::from_be_bytes(random_array::<8>()),
            replay: CounterWindow::new(4096),
            assembler: Assembler::new(max_message_bytes, 1 << 16),
            aad,
        })
    }

    fn seal_cell_into(&mut self, cell: &Cell, out: &mut Vec<u8>) -> Result<()> {
        let base = out.len();
        out.resize(base + BOLT_OVERHEAD + self.cell_size, 0);
        let mut nonce = [0u8; BOLT_NONCE_BYTES];
        nonce[..8].copy_from_slice(&self.send_prefix);
        nonce[8..].copy_from_slice(&self.send_counter.to_be_bytes());
        let tag = {
            let body = &mut out[base + BOLT_NONCE_BYTES..base + BOLT_NONCE_BYTES + self.cell_size];
            pack_cell_into_zero(cell, self.cell_size, body)?;
            Aegis128L::<BOLT_TAG_BYTES>::new(&self.send_key, &nonce)
                .encrypt_in_place(body, &self.aad)
        };
        out[base..base + BOLT_NONCE_BYTES].copy_from_slice(&nonce);
        out[base + BOLT_NONCE_BYTES + self.cell_size..base + BOLT_OVERHEAD + self.cell_size]
            .copy_from_slice(&tag);
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
        let cell_len = BOLT_OVERHEAD + self.cell_size;
        Ok(flat.chunks(cell_len).map(|c| c.to_vec()).collect())
    }

    pub fn send_padding(&mut self) -> Result<Vec<u8>> {
        let msg_id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        let mut out = Vec::with_capacity(BOLT_OVERHEAD + self.cell_size);
        self.seal_cell_into(&Cell::padding(msg_id), &mut out)?;
        Ok(out)
    }

    /// Authenticate and decode one wire cell, borrowing the payload in place.
    /// Every cell has its own counter.
    pub fn receive_ref<'a>(&mut self, wire: &'a mut [u8]) -> Result<ReceivedRef<'a>> {
        if wire.len() != BOLT_OVERHEAD + self.cell_size {
            return Err(Error::Truncated);
        }
        let mut nonce = [0u8; BOLT_NONCE_BYTES];
        nonce.copy_from_slice(&wire[..BOLT_NONCE_BYTES]);
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&nonce[8..]);
        let counter = u64::from_be_bytes(counter_bytes);
        let tag_start = wire.len() - BOLT_TAG_BYTES;
        let mut tag = [0u8; BOLT_TAG_BYTES];
        tag.copy_from_slice(&wire[tag_start..]);
        if Aegis128L::<BOLT_TAG_BYTES>::new(&self.recv_key, &nonce)
            .decrypt_in_place(&mut wire[BOLT_NONCE_BYTES..tag_start], &tag, &self.aad)
            .is_err()
        {
            // Fail closed: never leave candidate plaintext behind on a bad tag.
            wire.fill(0);
            return Err(Error::Auth);
        }
        let view = unpack_cell_view(&wire[BOLT_NONCE_BYTES..tag_start], self.cell_size)?;
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
