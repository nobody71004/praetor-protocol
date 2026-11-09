//! PRAETOR/1 multiplexed TCP egress.
//!
//! One authenticated PRAETOR session carries many TCP streams. Each PRAETOR
//! message is one frame:
//!
//! ```text
//! u32 streamId || u8 op || payload
//!
//! CONNECT (1)  payload = u16 hostLen || host || u16 port
//! DATA    (2)  payload = opaque bytes, at most MAX_EGRESS_PAYLOAD
//! CLOSE   (3)  payload = empty
//! OK      (4)  server -> client, target connected
//! ERROR   (5)  server -> client, payload = UTF-8 reason
//! ```
//!
//! This module is byte-compatible with the JavaScript egress implementation in
//! `praetor/src/egress.js`, so the existing desktop client and Node proxy can
//! use a Rust exit. The frame layer runs inside PRAETOR's authenticated fixed
//! cells; this is a TCP proxy, not a TUN/IP tunnel.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::handshake;
use crate::ratchet::DEFAULT_INTERVAL;
use crate::wire::{
    Received, SecureChannel, CELL_HEADER_BYTES, CELL_OVERHEAD, DEFAULT_CELL_SIZE, MAX_CELL_SIZE,
};

pub const FRAME_HEADER_BYTES: usize = 5;
pub const EGRESS_CONNECT: u8 = 1;
pub const EGRESS_DATA: u8 = 2;
pub const EGRESS_CLOSE: u8 = 3;
pub const EGRESS_OK: u8 = 4;
pub const EGRESS_ERROR: u8 = 5;
pub const MAX_EGRESS_PAYLOAD: usize = 32 * 1024;

const MAX_HOST_BYTES: usize = 255;
const MAX_HANDSHAKE_FRAME: usize = 1 << 20;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Server-side egress settings.
#[derive(Clone, Debug)]
pub struct EgressConfig {
    pub cell_size: usize,
    pub max_message_bytes: usize,
    pub connect_timeout: Duration,
    pub log: bool,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            cell_size: DEFAULT_CELL_SIZE,
            max_message_bytes: 64 << 20,
            connect_timeout: Duration::from_secs(10),
            log: true,
        }
    }
}

/// Encode one egress frame.
pub fn encode_frame(stream_id: u32, op: u8, payload: &[u8]) -> Result<Vec<u8>> {
    if !(EGRESS_CONNECT..=EGRESS_ERROR).contains(&op) {
        return Err(Error::Range);
    }
    if payload.len() > MAX_EGRESS_PAYLOAD {
        return Err(Error::Range);
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.push(op);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode one egress frame, borrowing the payload.
pub fn decode_frame(buf: &[u8]) -> Result<(u32, u8, &[u8])> {
    if buf.len() < FRAME_HEADER_BYTES || buf.len() - FRAME_HEADER_BYTES > MAX_EGRESS_PAYLOAD {
        return Err(Error::Malformed);
    }
    let stream_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let op = buf[4];
    if !(EGRESS_CONNECT..=EGRESS_ERROR).contains(&op) {
        return Err(Error::Malformed);
    }
    Ok((stream_id, op, &buf[FRAME_HEADER_BYTES..]))
}

/// Encode a CONNECT payload: `u16 hostLen || host || u16 port`.
pub fn encode_connect(host: &str, port: u16) -> Result<Vec<u8>> {
    let name = host.as_bytes();
    if name.is_empty() || name.len() > MAX_HOST_BYTES || port == 0 {
        return Err(Error::Range);
    }
    let mut out = Vec::with_capacity(2 + name.len() + 2);
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// Decode a CONNECT payload, rejecting non-UTF-8 hosts and malformed lengths.
pub fn decode_connect(payload: &[u8]) -> Result<(String, u16)> {
    if payload.len() < 4 {
        return Err(Error::Malformed);
    }
    let name_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if name_len == 0 || name_len > MAX_HOST_BYTES || payload.len() != 4 + name_len {
        return Err(Error::Malformed);
    }
    let host = std::str::from_utf8(&payload[2..2 + name_len])
        .map_err(|_| Error::Malformed)?
        .to_string();
    let port = u16::from_be_bytes([payload[2 + name_len], payload[3 + name_len]]);
    if port == 0 {
        return Err(Error::Malformed);
    }
    Ok((host, port))
}

/// Listen for PRAETOR clients and forward each session's TCP streams.
pub fn serve(
    listener: TcpListener,
    server_pk: Vec<u8>,
    server_sk: Vec<u8>,
    config: EgressConfig,
) -> io::Result<()> {
    let pk = Arc::new(server_pk);
    let sk = Arc::new(server_sk);
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(err) => {
                if config.log {
                    eprintln!("[praetor-egress] accept failed: {err}");
                }
                continue;
            }
        };
        let pk = Arc::clone(&pk);
        let sk = Arc::clone(&sk);
        let config = config.clone();
        thread::spawn(move || {
            if let Err(err) = handle_connection(stream, &pk, &sk, &config) {
                if config.log {
                    eprintln!("[praetor-egress] session ended: {err}");
                }
            }
        });
    }
    Ok(())
}

/// Handle one accepted TCP connection: handshake, then multiplexed egress.
pub fn handle_connection(
    mut stream: TcpStream,
    server_pk: &[u8],
    server_sk: &[u8],
    config: &EgressConfig,
) -> io::Result<()> {
    if config.cell_size < CELL_HEADER_BYTES + 1 || config.cell_size > MAX_CELL_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cell size out of range",
        ));
    }

    let session = server_handshake(&mut stream, server_pk, server_sk)?;
    if config.log {
        eprintln!(
            "[praetor-egress] session {} opened",
            hex::encode(&session.session_id[..8])
        );
    }

    let send_channel = SecureChannel::new(
        session.send_chain,
        session.recv_chain,
        config.cell_size,
        DEFAULT_INTERVAL,
        config.max_message_bytes,
    )
    .map_err(crypto_err)?;
    let mut recv_channel = SecureChannel::new(
        session.send_chain,
        session.recv_chain,
        config.cell_size,
        DEFAULT_INTERVAL,
        config.max_message_bytes,
    )
    .map_err(crypto_err)?;

    let writer_stream = stream.try_clone()?;
    let writer = Arc::new(Mutex::new(Writer {
        stream: writer_stream,
        channel: send_channel,
    }));
    let targets: Targets = Arc::new(Mutex::new(HashMap::new()));
    let cell_len = CELL_OVERHEAD + config.cell_size;
    let mut buf = vec![0u8; cell_len];

    loop {
        if stream.read_exact(&mut buf).is_err() {
            break;
        }
        match recv_channel.receive(&buf) {
            Ok(Received::Complete { data, .. }) => {
                if let Err(err) = dispatch(&data, &writer, &targets, config) {
                    if config.log {
                        eprintln!("[praetor-egress] frame rejected: {err}");
                    }
                    break;
                }
            }
            Ok(_) => {}
            Err(err) => {
                if config.log {
                    eprintln!("[praetor-egress] cell rejected: {}", err.code());
                }
                break;
            }
        }
    }

    if let Ok(mut map) = targets.lock() {
        for (_, target) in map.drain() {
            let _ = target.shutdown(Shutdown::Both);
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    if let Ok(writer) = writer.lock() {
        let _ = writer.stream.shutdown(Shutdown::Both);
    }
    if config.log {
        eprintln!(
            "[praetor-egress] session {} closed",
            hex::encode(&session.session_id[..8])
        );
    }
    Ok(())
}

struct Writer {
    stream: TcpStream,
    channel: SecureChannel,
}

impl Writer {
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        let cells = match self.channel.send(frame) {
            Ok(cells) => cells,
            Err(err) => {
                let _ = self.stream.shutdown(Shutdown::Both);
                return Err(crypto_err(err));
            }
        };
        for cell in cells {
            if let Err(err) = self.stream.write_all(&cell) {
                let _ = self.stream.shutdown(Shutdown::Both);
                return Err(err);
            }
        }
        if let Err(err) = self.stream.flush() {
            let _ = self.stream.shutdown(Shutdown::Both);
            return Err(err);
        }
        Ok(())
    }
}

type Targets = Arc<Mutex<HashMap<u32, TcpStream>>>;

fn write_egress_frame(
    writer: &Mutex<Writer>,
    stream_id: u32,
    op: u8,
    payload: &[u8],
) -> io::Result<()> {
    let frame = encode_frame(stream_id, op, payload).map_err(crypto_err)?;
    let mut writer = writer
        .lock()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "egress writer poisoned"))?;
    writer.send(&frame)
}

fn dispatch(
    frame: &[u8],
    writer: &Arc<Mutex<Writer>>,
    targets: &Targets,
    config: &EgressConfig,
) -> io::Result<()> {
    let (stream_id, op, payload) = decode_frame(frame).map_err(crypto_err)?;
    match op {
        EGRESS_CONNECT => connect_stream(stream_id, payload, writer, targets, config),
        EGRESS_DATA => {
            let target = targets
                .lock()
                .ok()
                .and_then(|map| map.get(&stream_id).and_then(|s| s.try_clone().ok()));
            if let Some(mut target) = target {
                if let Err(err) = target.write_all(payload) {
                    if let Ok(mut map) = targets.lock() {
                        map.remove(&stream_id);
                    }
                    let reason = err.to_string();
                    let _ = write_egress_frame(writer, stream_id, EGRESS_ERROR, reason.as_bytes());
                    let _ = write_egress_frame(writer, stream_id, EGRESS_CLOSE, &[]);
                }
            }
            Ok(())
        }
        EGRESS_CLOSE => {
            let target = targets
                .lock()
                .ok()
                .and_then(|mut map| map.remove(&stream_id));
            if let Some(target) = target {
                let _ = target.shutdown(Shutdown::Write);
            }
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected client egress op",
        )),
    }
}

fn connect_stream(
    stream_id: u32,
    payload: &[u8],
    writer: &Arc<Mutex<Writer>>,
    targets: &Targets,
    config: &EgressConfig,
) -> io::Result<()> {
    let (host, port) = match decode_connect(payload) {
        Ok(target) => target,
        Err(_) => {
            let _ = write_egress_frame(writer, stream_id, EGRESS_ERROR, b"bad connect frame");
            return Ok(());
        }
    };
    if targets
        .lock()
        .map(|map| map.contains_key(&stream_id))
        .unwrap_or(false)
    {
        let _ = write_egress_frame(writer, stream_id, EGRESS_ERROR, b"duplicate stream id");
        return Ok(());
    }

    let target = match connect_target(&host, port, config.connect_timeout) {
        Ok(target) => target,
        Err(err) => {
            let _ = write_egress_frame(writer, stream_id, EGRESS_ERROR, err.to_string().as_bytes());
            return Ok(());
        }
    };
    let reader_target = match target.try_clone() {
        Ok(target) => target,
        Err(err) => {
            let _ = write_egress_frame(writer, stream_id, EGRESS_ERROR, err.to_string().as_bytes());
            return Ok(());
        }
    };
    if let Ok(mut map) = targets.lock() {
        map.insert(stream_id, target);
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "egress stream map poisoned",
        ));
    }

    if let Err(err) = write_egress_frame(writer, stream_id, EGRESS_OK, &[]) {
        if let Ok(mut map) = targets.lock() {
            map.remove(&stream_id);
        }
        return Err(err);
    }

    spawn_target_reader(
        stream_id,
        reader_target,
        Arc::clone(writer),
        Arc::clone(targets),
        config.log,
    );
    Ok(())
}

fn spawn_target_reader(
    stream_id: u32,
    mut target: TcpStream,
    writer: Arc<Mutex<Writer>>,
    targets: Targets,
    log: bool,
) {
    thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        let mut failure: Option<String> = None;
        loop {
            match target.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(err) = write_egress_frame(&writer, stream_id, EGRESS_DATA, &buf[..n])
                    {
                        failure = Some(err.to_string());
                        break;
                    }
                }
                Err(err) => {
                    failure = Some(err.to_string());
                    break;
                }
            }
        }
        if let Ok(mut map) = targets.lock() {
            map.remove(&stream_id);
        }
        if let Some(reason) = failure {
            if log {
                eprintln!("[praetor-egress] stream {stream_id} failed: {reason}");
            }
            let _ = write_egress_frame(&writer, stream_id, EGRESS_ERROR, reason.as_bytes());
        }
        let _ = write_egress_frame(&writer, stream_id, EGRESS_CLOSE, &[]);
        let _ = target.shutdown(Shutdown::Both);
    });
}

fn connect_target(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "target has no addresses",
        ));
    }
    let mut last = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(err) => last = Some(err),
        }
    }
    Err(last.unwrap())
}

fn server_handshake(
    stream: &mut TcpStream,
    server_pk: &[u8],
    server_sk: &[u8],
) -> io::Result<handshake::Session> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let c1 = read_handshake_frame(stream)?;
    let (s1, mut state) =
        handshake::server_respond_with_pk(server_pk, server_sk, &c1).map_err(crypto_err)?;
    write_handshake_frame(stream, &s1)?;
    let confirm = read_handshake_frame(stream)?;
    let session = handshake::server_finish(&mut state, &confirm).map_err(crypto_err)?;
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(session)
}

fn read_handshake_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    let len = u32::from_be_bytes(head) as usize;
    if len == 0 || len > MAX_HANDSHAKE_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad handshake frame length",
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn write_handshake_frame(stream: &mut TcpStream, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "handshake frame too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn crypto_err(err: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frame = encode_frame(7, EGRESS_DATA, b"hello").unwrap();
        assert_eq!(frame.len(), FRAME_HEADER_BYTES + 5);
        let (id, op, payload) = decode_frame(&frame).unwrap();
        assert_eq!(id, 7);
        assert_eq!(op, EGRESS_DATA);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn frame_rejects_bad_input() {
        assert!(encode_frame(1, 0, b"").is_err());
        assert!(encode_frame(1, 6, b"").is_err());
        assert!(encode_frame(1, EGRESS_DATA, &vec![0u8; MAX_EGRESS_PAYLOAD + 1]).is_err());
        assert!(decode_frame(&[0u8; 4]).is_err());
        assert!(decode_frame(&[0, 0, 0, 1, 9]).is_err());
        assert!(decode_frame(&vec![0u8; FRAME_HEADER_BYTES + MAX_EGRESS_PAYLOAD + 1]).is_err());
    }

    #[test]
    fn connect_roundtrip() {
        let payload = encode_connect("example.com", 443).unwrap();
        let (host, port) = decode_connect(&payload).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn connect_rejects_bad_input() {
        assert!(encode_connect("", 443).is_err());
        assert!(encode_connect("host", 0).is_err());
        assert!(encode_connect(&"a".repeat(MAX_HOST_BYTES + 1), 443).is_err());
        assert!(decode_connect(&[]).is_err());
        assert!(decode_connect(&[0, 0, 0, 0]).is_err());
        let mut bad = encode_connect("host", 443).unwrap();
        bad[2] = 0xff;
        assert!(decode_connect(&bad).is_err());
    }
}
