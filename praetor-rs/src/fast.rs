//! PRAETOR/FAST — an opt-in, performance-oriented fixed-cell transport.
//!
//! This profile keeps the PRAETOR handshake and fixed-size cells, but replaces
//! the PSEAL envelope with one in-place AES-256-GCM pass and a unique nonce.
//! It is deliberately **not** the default:
//!
//! * no SIV / nonce-misuse resistance;
//! * no independent key-commitment tag;
//! * a stateful nonce counter must never be reused with the same key.
//!
//! The result is a WireGuard-class packet path with PRAETOR's post-quantum
//! handshake and fixed-cell metadata hiding. Use PSEAL for the stronger
//! envelope guarantees.
//!
//! The AEAD backend is `ring`, the same implementation WireGuard's userspace
//! stack (boringtun) uses. ring dispatches AES-NI/CLMUL at runtime, so this is
//! a fair protocol comparison rather than a crypto-library comparison.

use std::collections::{HashSet, VecDeque};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

use crate::error::{Error, Result};
use crate::util::{random_array, u16be};
use crate::wire::{
    pack_cell_into_zero, unpack_cell, Assembler, Cell, Received, CELL_HEADER_BYTES, CELL_PAD,
    MAX_CELL_SIZE,
};

/// AES-256-GCM fixed nonce and tag sizes (ring `NONCE_LEN` / `TAG_LEN`).
pub const FAST_NONCE_BYTES: usize = 12;
pub const FAST_TAG_BYTES: usize = 16;
pub const FAST_OVERHEAD: usize = FAST_NONCE_BYTES + FAST_TAG_BYTES;
const LABEL: &[u8] = b"PRAETOR/FAST/1";

/// Bounded replay window over monotonically increasing nonce counters.
struct CounterWindow {
    capacity: usize,
    seen: HashSet<u32>,
    order: VecDeque<u32>,
}

impl CounterWindow {
    fn new(capacity: usize) -> Self {
        Self { capacity, seen: HashSet::new(), order: VecDeque::new() }
    }

    fn accept(&mut self, counter: u32) -> Result<()> {
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

/// A full-duplex fixed-cell channel using one in-place AES-256-GCM pass per cell.
pub struct FastChannel {
    cell_size: usize,
    payload_capacity: usize,
    send: LessSafeKey,
    recv: LessSafeKey,
    send_nonce_prefix: [u8; 8],
    send_counter: u32,
    next_msg_id: u64,
    replay: CounterWindow,
    assembler: Assembler,
    aad: Vec<u8>,
}

impl FastChannel {
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
            send: LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM, &send_key).map_err(|_| Error::Key)?,
            ),
            recv: LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM, &recv_key).map_err(|_| Error::Key)?,
            ),
            send_nonce_prefix: random_array::<8>(),
            send_counter: 0,
            next_msg_id: u64::from_be_bytes(random_array::<8>()),
            replay: CounterWindow::new(4096),
            assembler: Assembler::new(max_message_bytes, 1 << 16),
            aad,
        })
    }

    fn seal(&mut self, cell: &Cell) -> Result<Vec<u8>> {
        let mut wire = vec![0u8; FAST_OVERHEAD + self.cell_size];
        let mut nonce = [0u8; FAST_NONCE_BYTES];
        nonce[..8].copy_from_slice(&self.send_nonce_prefix);
        nonce[8..].copy_from_slice(&self.send_counter.to_be_bytes());
        let body = FAST_NONCE_BYTES..FAST_NONCE_BYTES + self.cell_size;
        pack_cell_into_zero(cell, self.cell_size, &mut wire[body.clone()])?;
        let tag = self
            .send
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(self.aad.as_slice()),
                &mut wire[body.clone()],
            )
            .map_err(|_| Error::Auth)?;
        wire[..FAST_NONCE_BYTES].copy_from_slice(&nonce);
        wire[body.end..].copy_from_slice(tag.as_ref());
        self.send_counter = self.send_counter.checked_add(1).ok_or(Error::Range)?;
        Ok(wire)
    }

    /// Fragment and seal one application message.
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let count = ((data.len() + self.payload_capacity - 1) / self.payload_capacity).max(1);
        if count > u16::MAX as usize {
            return Err(Error::Policy);
        }
        let msg_id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let from = i * self.payload_capacity;
            let to = (from + self.payload_capacity).min(data.len());
            let cell = Cell::data(msg_id, i as u16, count as u16, &data[from..to]);
            out.push(self.seal(&cell)?);
        }
        Ok(out)
    }

    pub fn send_padding(&mut self) -> Result<Vec<u8>> {
        let msg_id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        self.seal(&Cell::padding(msg_id))
    }

    /// Authenticate and decode one wire cell in place. Every cell has its own counter.
    pub fn receive(&mut self, wire: &mut [u8]) -> Result<Received> {
        if wire.len() < FAST_OVERHEAD + CELL_HEADER_BYTES + 1 {
            return Err(Error::Truncated);
        }
        let mut nonce = [0u8; FAST_NONCE_BYTES];
        nonce.copy_from_slice(&wire[..FAST_NONCE_BYTES]);
        let mut counter_bytes = [0u8; 4];
        counter_bytes.copy_from_slice(&nonce[8..]);
        let counter = u32::from_be_bytes(counter_bytes);
        if wire.len() != FAST_OVERHEAD + self.cell_size {
            return Err(Error::Truncated);
        }
        // ring authenticates and decrypts the cell in place, so there is no
        // plaintext copy on the receive path. The nonce prefix is excluded
        // because ring writes recovered plaintext at the start of its buffer.
        self.recv
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(self.aad.as_slice()),
                &mut wire[FAST_NONCE_BYTES..],
            )
            .map_err(|_| Error::Auth)?;
        let cell = unpack_cell(
            &wire[FAST_NONCE_BYTES..FAST_NONCE_BYTES + self.cell_size],
            self.cell_size,
        )?;
        self.replay.accept(counter)?;
        if cell.kind == CELL_PAD {
            return Ok(Received::Padding);
        }
        if cell.frag_count == 1 {
            return Ok(Received::Complete { msg_id: cell.msg_id, data: cell.payload });
        }
        match self.assembler.push(&cell)? {
            None => Ok(Received::Fragment { kind: cell.kind, msg_id: cell.msg_id }),
            Some((msg_id, data)) => Ok(Received::Complete { msg_id, data }),
        }
    }
}
