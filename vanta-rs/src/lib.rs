//! VANTA/1 — Rust implementation.
//!
//! Byte-compatible with the JavaScript reference; shared vectors live in
//! `../vectors/vanta-vectors.json`.

pub mod aead;
pub mod container;
pub mod error;
pub mod guard;
pub mod handshake;
pub mod padme;
pub mod ratchet;
pub mod util;
pub mod wire;
pub mod xwing;

pub use error::{Error, Result};

pub const VERSION: &str = "VANTA/1";
