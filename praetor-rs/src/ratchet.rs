use std::collections::HashMap;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::util::{hkdf_sha256, hmac_sha256, u32be};

const LABEL_RATCHET: &[u8] = b"PRAETOR/1/ratchet";
const LABEL_RECORD_SALT: &[u8] = b"PRAETOR/1/record";
const LABEL_RECORD_INFO: &[u8] = b"PRAETOR/1/epoch";

pub const DEFAULT_INTERVAL: u32 = 1024;

pub fn derive_record_key(chain: &[u8; 32], epoch: u32) -> [u8; 32] {
    let mut info = Vec::with_capacity(LABEL_RECORD_INFO.len() + 4);
    info.extend_from_slice(LABEL_RECORD_INFO);
    info.extend_from_slice(&u32be(epoch));
    let mut out = [0u8; 32];
    hkdf_sha256(chain, LABEL_RECORD_SALT, &info, &mut out);
    out
}

pub fn step_chain(chain: &[u8; 32], epoch: u32) -> [u8; 32] {
    hmac_sha256(chain, &[LABEL_RATCHET, &u32be(epoch)])
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SendRatchet {
    chain: [u8; 32],
    key: [u8; 32],
    interval: u32,
    index: u64,
    epoch: u32,
}

impl SendRatchet {
    pub fn new(chain: [u8; 32], interval: u32) -> Result<Self> {
        if interval == 0 {
            return Err(Error::Range);
        }
        let key = derive_record_key(&chain, 0);
        Ok(Self { chain, key, interval, index: 0, epoch: 0 })
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn peek(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn next(&mut self) -> [u8; 32] {
        let out = self.key;
        self.index += 1;
        let next_epoch = (self.index / self.interval as u64) as u32;
        if next_epoch != self.epoch {
            self.chain = step_chain(&self.chain, self.epoch);
            self.epoch = next_epoch;
            self.key = derive_record_key(&self.chain, self.epoch);
        }
        out
    }
}

pub struct RecvRatchet {
    chains: HashMap<u32, [u8; 32]>,
    keys: HashMap<u32, [u8; 32]>,
    interval: u32,
    lookahead: u32,
    index: u64,
}

impl Drop for RecvRatchet {
    fn drop(&mut self) {
        for v in self.chains.values_mut() {
            v.zeroize();
        }
        for v in self.keys.values_mut() {
            v.zeroize();
        }
    }
}

impl RecvRatchet {
    pub fn new(chain: [u8; 32], interval: u32, lookahead: u32) -> Result<Self> {
        if interval == 0 {
            return Err(Error::Range);
        }
        let mut chains = HashMap::new();
        chains.insert(0, chain);
        Ok(Self { chains, keys: HashMap::new(), interval, lookahead, index: 0 })
    }

    fn chain_at(&mut self, epoch: u32) -> [u8; 32] {
        if let Some(c) = self.chains.get(&epoch) {
            return *c;
        }
        let prev = self.chain_at(epoch - 1);
        let c = step_chain(&prev, epoch - 1);
        self.chains.insert(epoch, c);
        c
    }

    fn key_at(&mut self, epoch: u32) -> [u8; 32] {
        if let Some(k) = self.keys.get(&epoch) {
            return *k;
        }
        let chain = self.chain_at(epoch);
        let k = derive_record_key(&chain, epoch);
        self.keys.insert(epoch, k);
        k
    }

    /// Candidate epochs, closest to the expected one first.
    pub fn candidates(&mut self) -> Vec<(u32, [u8; 32])> {
        let expected = (self.index / self.interval as u64) as u32;
        let start = expected.saturating_sub(1);
        let end = expected.saturating_add(self.lookahead);
        let mut out: Vec<(u32, [u8; 32])> = (start..=end).map(|e| (e, self.key_at(e))).collect();
        out.sort_by_key(|(e, _)| (*e as i64 - expected as i64).unsigned_abs());
        out
    }

    pub fn commit(&mut self, _epoch: u32) {
        self.index += 1;
        let floor = self.floor();
        self.keys.retain(|e, _| *e >= floor);
        self.chains.retain(|e, _| *e >= floor);
    }

    /// Oldest epoch that can still be needed for trial decryption.
    pub fn floor(&self) -> u32 {
        let expected = (self.index / self.interval as u64) as u32;
        expected.saturating_sub(self.lookahead + 1)
    }

    pub fn opened(&self) -> u64 {
        self.index
    }
}
