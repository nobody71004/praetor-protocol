use std::collections::{HashMap, HashSet, VecDeque};

use crate::aead::SealKey;
use crate::error::{Error, Result};
use crate::ratchet::{RecvRatchet, SendRatchet};
use crate::util::{read_u16, read_u64, u16be};

pub const CELL_HEADER_BYTES: usize = 16;
pub const CELL_OVERHEAD: usize = 80;
pub const DEFAULT_CELL_SIZE: usize = 1024;
pub const MAX_CELL_SIZE: usize = 65535 - CELL_HEADER_BYTES;

pub const CELL_DATA: u8 = 0;
pub const CELL_PAD: u8 = 1;
pub const CELL_CTRL: u8 = 2;
pub const CELL_FIN: u8 = 3;

const LABEL_CELL: &[u8] = b"PRAETOR/1/cell";

#[derive(Debug, Clone)]
pub struct Cell {
    pub kind: u8,
    pub flags: u8,
    pub frag_index: u16,
    pub frag_count: u16,
    pub msg_id: u64,
    pub payload: Vec<u8>,
}

impl Cell {
    pub fn data(msg_id: u64, frag_index: u16, frag_count: u16, payload: &[u8]) -> Self {
        let kind = if frag_index + 1 == frag_count { CELL_FIN } else { CELL_DATA };
        Self { kind, flags: 0, frag_index, frag_count, msg_id, payload: payload.to_vec() }
    }

    pub fn padding(msg_id: u64) -> Self {
        Self { kind: CELL_PAD, flags: 0, frag_index: 0, frag_count: 1, msg_id, payload: Vec::new() }
    }
}

fn pack_cell_inner(cell: &Cell, cell_size: usize, out: &mut [u8], random_pad: bool) -> Result<()> {
    if out.len() != cell_size {
        return Err(Error::Range);
    }
    if cell_size < CELL_HEADER_BYTES + 1 || cell_size > MAX_CELL_SIZE {
        return Err(Error::Range);
    }
    if cell.payload.len() > cell_size - CELL_HEADER_BYTES {
        return Err(Error::Range);
    }
    if cell.frag_count == 0 || cell.frag_index >= cell.frag_count {
        return Err(Error::Range);
    }
    if cell.kind > CELL_FIN {
        return Err(Error::Range);
    }
    out[0] = cell.kind;
    out[1] = cell.flags;
    out[2..4].copy_from_slice(&cell.frag_index.to_be_bytes());
    out[4..6].copy_from_slice(&cell.frag_count.to_be_bytes());
    out[6..14].copy_from_slice(&cell.msg_id.to_be_bytes());
    out[14..16].copy_from_slice(&(cell.payload.len() as u16).to_be_bytes());
    out[16..16 + cell.payload.len()].copy_from_slice(&cell.payload);
    let pad_from = 16 + cell.payload.len();
    if pad_from < cell_size {
        if random_pad {
            getrandom::getrandom(&mut out[pad_from..]).map_err(|_| Error::Malformed)?;
        } else {
            out[pad_from..].fill(0);
        }
    }
    Ok(())
}

pub fn pack_cell_into(cell: &Cell, cell_size: usize, out: &mut [u8]) -> Result<()> {
    pack_cell_inner(cell, cell_size, out, true)
}

/// Zero padding is safe for an authenticated fixed cell: the plaintext pad is
/// encrypted, and the wire length already hides payload length. FAST uses this
/// to avoid a syscall per cell.
pub fn pack_cell_into_zero(cell: &Cell, cell_size: usize, out: &mut [u8]) -> Result<()> {
    pack_cell_inner(cell, cell_size, out, false)
}

pub fn pack_cell(cell: &Cell, cell_size: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; cell_size];
    pack_cell_into(cell, cell_size, &mut out)?;
    Ok(out)
}

pub fn unpack_cell(plain: &[u8], cell_size: usize) -> Result<Cell> {
    if plain.len() != cell_size {
        return Err(Error::Malformed);
    }
    if cell_size < CELL_HEADER_BYTES + 1 {
        return Err(Error::Malformed);
    }
    let kind = plain[0];
    if kind > CELL_FIN {
        return Err(Error::Malformed);
    }
    let frag_index = read_u16(plain, 2);
    let frag_count = read_u16(plain, 4);
    if frag_count == 0 || frag_index >= frag_count {
        return Err(Error::Malformed);
    }
    let msg_id = read_u64(plain, 6);
    let payload_len = read_u16(plain, 14) as usize;
    if payload_len > cell_size - CELL_HEADER_BYTES {
        return Err(Error::Malformed);
    }
    Ok(Cell {
        kind,
        flags: plain[1],
        frag_index,
        frag_count,
        msg_id,
        payload: plain[16..16 + payload_len].to_vec(),
    })
}

pub struct CellCipher {
    seal: SealKey,
    cell_size: usize,
    aad: Vec<u8>,
}

impl CellCipher {
    pub fn new(record_key: &[u8; 32], cell_size: usize) -> Result<Self> {
        if cell_size < CELL_HEADER_BYTES + 1 || cell_size > MAX_CELL_SIZE {
            return Err(Error::Range);
        }
        let mut aad = Vec::with_capacity(LABEL_CELL.len() + 2);
        aad.extend_from_slice(LABEL_CELL);
        aad.extend_from_slice(&u16be(cell_size as u16));
        Ok(Self { seal: SealKey::new(record_key)?, cell_size, aad })
    }

    pub fn seal_cell(&self, cell: &Cell) -> Result<Vec<u8>> {
        let plain = pack_cell(cell, self.cell_size)?;
        self.seal.seal_random(&plain, &self.aad)
    }

    pub fn open_cell(&self, wire: &[u8]) -> Result<Cell> {
        let plain = self.seal.open(wire, &self.aad, false)?;
        unpack_cell(&plain, self.cell_size)
    }
}

pub struct ReplayWindow {
    capacity: usize,
    seen: HashMap<u64, HashSet<u16>>,
    order: VecDeque<u64>,
}

impl ReplayWindow {
    pub fn new(capacity: usize) -> Self {
        Self { capacity, seen: HashMap::new(), order: VecDeque::new() }
    }

    pub fn accept(&mut self, msg_id: u64, frag: u16) -> Result<()> {
        let entry = self.seen.entry(msg_id).or_insert_with(|| {
            self.order.push_back(msg_id);
            HashSet::new()
        });
        if !entry.insert(frag) {
            return Err(Error::Replay);
        }
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        Ok(())
    }
}

struct Slot {
    count: u16,
    parts: Vec<Option<Vec<u8>>>,
    have: usize,
    bytes: usize,
}

pub struct Assembler {
    pending: HashMap<u64, Slot>,
    max_message_bytes: usize,
    max_fragments: usize,
}

impl Assembler {
    pub fn new(max_message_bytes: usize, max_fragments: usize) -> Self {
        Self { pending: HashMap::new(), max_message_bytes, max_fragments }
    }

    pub fn push(&mut self, cell: &Cell) -> Result<Option<(u64, Vec<u8>)>> {
        let slot = match self.pending.get_mut(&cell.msg_id) {
            Some(s) => s,
            None => {
                if cell.frag_count as usize > self.max_fragments {
                    return Err(Error::Policy);
                }
                self.pending.insert(
                    cell.msg_id,
                    Slot {
                        count: cell.frag_count,
                        parts: vec![None; cell.frag_count as usize],
                        have: 0,
                        bytes: 0,
                    },
                );
                self.pending.get_mut(&cell.msg_id).unwrap()
            }
        };
        if slot.count != cell.frag_count {
            return Err(Error::Malformed);
        }
        if slot.parts[cell.frag_index as usize].is_some() {
            return Ok(None);
        }
        slot.bytes += cell.payload.len();
        if slot.bytes > self.max_message_bytes {
            return Err(Error::Policy);
        }
        slot.parts[cell.frag_index as usize] = Some(cell.payload.clone());
        slot.have += 1;
        if slot.have != slot.count as usize {
            return Ok(None);
        }
        let slot = self.pending.remove(&cell.msg_id).unwrap();
        let mut data = Vec::with_capacity(slot.bytes);
        for p in slot.parts {
            data.extend_from_slice(&p.unwrap());
        }
        Ok(Some((cell.msg_id, data)))
    }
}

#[derive(Debug)]
pub enum Received {
    Padding,
    Fragment { kind: u8, msg_id: u64 },
    Complete { msg_id: u64, data: Vec<u8> },
}

pub struct SecureChannel {
    cell_size: usize,
    payload_capacity: usize,
    send: SendRatchet,
    recv: RecvRatchet,
    replay: ReplayWindow,
    assembler: Assembler,
    next_msg_id: u64,
    send_cipher: Option<(u32, CellCipher)>,
    recv_ciphers: HashMap<u32, CellCipher>,
}

impl SecureChannel {
    pub fn new(
        send_chain: [u8; 32],
        recv_chain: [u8; 32],
        cell_size: usize,
        interval: u32,
        max_message_bytes: usize,
    ) -> Result<Self> {
        if cell_size < CELL_HEADER_BYTES + 1 || cell_size > MAX_CELL_SIZE {
            return Err(Error::Range);
        }
        let start: [u8; 8] = crate::util::random_array();
        let next_msg_id = u64::from_be_bytes(start);
        Ok(Self {
            cell_size,
            payload_capacity: cell_size - CELL_HEADER_BYTES,
            send: SendRatchet::new(send_chain, interval)?,
            recv: RecvRatchet::new(recv_chain, interval, 2)?,
            replay: ReplayWindow::new(4096),
            assembler: Assembler::new(max_message_bytes, 1 << 16),
            next_msg_id,
            send_cipher: None,
            recv_ciphers: HashMap::new(),
        })
    }

    fn cipher(&mut self) -> Result<&CellCipher> {
        let epoch = self.send.epoch();
        let stale = self.send_cipher.as_ref().map(|(e, _)| *e) != Some(epoch);
        if stale {
            let key = *self.send.peek();
            self.send_cipher = Some((epoch, CellCipher::new(&key, self.cell_size)?));
        }
        Ok(&self.send_cipher.as_ref().unwrap().1)
    }

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
            let payload = &data[from..to];
            let cell = Cell::data(msg_id, i as u16, count as u16, payload);
            let sealed = self.cipher()?.seal_cell(&cell)?;
            out.push(sealed);
            self.send.next();
        }
        Ok(out)
    }

    pub fn send_padding(&mut self) -> Result<Vec<u8>> {
        let msg_id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        let sealed = self.cipher()?.seal_cell(&Cell::padding(msg_id))?;
        self.send.next();
        Ok(sealed)
    }

    pub fn receive(&mut self, wire: &[u8]) -> Result<Received> {
        let candidates = self.recv.candidates();
        let mut opened: Option<(u32, Cell)> = None;
        for (epoch, key) in candidates {
            // The key schedule is expensive relative to a 1 KiB cell. Keep one
            // cipher per candidate epoch instead of rebuilding it per packet.
            if !self.recv_ciphers.contains_key(&epoch) {
                self.recv_ciphers
                    .insert(epoch, CellCipher::new(&key, self.cell_size)?);
            }
            let cipher = self.recv_ciphers.get(&epoch).unwrap();
            if let Ok(cell) = cipher.open_cell(wire) {
                opened = Some((epoch, cell));
                break;
            }
        }
        let (epoch, cell) = opened.ok_or(Error::Auth)?;
        self.replay.accept(cell.msg_id, cell.frag_index)?;
        self.recv.commit(epoch);
        let floor = self.recv.floor();
        self.recv_ciphers.retain(|e, _| *e >= floor);
        if cell.kind == CELL_PAD {
            return Ok(Received::Padding);
        }
        match self.assembler.push(&cell)? {
            None => Ok(Received::Fragment { kind: cell.kind, msg_id: cell.msg_id }),
            Some((msg_id, data)) => Ok(Received::Complete { msg_id, data }),
        }
    }
}

pub fn cover_schedule(count: usize, interval_ms: f64, jitter: f64) -> Vec<f64> {
    let mut out = Vec::with_capacity(count);
    let mut t = 0.0;
    for _ in 0..count {
        t += interval_ms;
        let r = if jitter > 0.0 {
            let b: [u8; 4] = crate::util::random_array();
            let u = u32::from_be_bytes(b) as f64 / u32::MAX as f64;
            (u * 2.0 - 1.0) * jitter * interval_ms
        } else {
            0.0
        };
        out.push((t + r).max(0.0));
    }
    out
}

#[allow(dead_code)]
fn _labels() -> &'static [u8] {
    &[0]
}
