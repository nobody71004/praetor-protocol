//! PRAETOR/1 — Rust implementation.
//!
//! Byte-compatible with the JavaScript reference; shared vectors live in
//! `../vectors/praetor-vectors.json`.

pub mod aead;
pub mod bolt;
pub mod container;
pub mod egress;
pub mod error;
pub mod fast;
pub mod guard;
pub mod handshake;
pub mod padme;
pub mod pmarine;
pub mod ratchet;
pub mod util;
pub mod wire;
pub mod xwing;

pub use error::{Error, Result};

pub const VERSION: &str = "PRAETOR/1";
