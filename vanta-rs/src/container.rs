use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use crate::aead::SealKey;
use crate::error::{Error, Result};
use crate::padme::padme;
use crate::util::{read_u32, read_u64, u16be, u32be, u64be};

const LABEL_HEADER: &[u8] = b"VANTA/1/file/header";
const LABEL_CHUNK: &[u8] = b"VANTA/1/file/chunk";

pub const DEFAULT_CHUNK_SIZE: usize = 1 << 20;
pub const HEADER_PLAIN_BYTES: usize = 30;

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u8,
    pub suite: u8,
    pub chunk_size: usize,
    pub total_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub name: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Meta {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub chunks: u64,
    pub total: u64,
}

fn chunk_aad(index: u64, last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LABEL_CHUNK.len() + 9);
    aad.extend_from_slice(LABEL_CHUNK);
    aad.extend_from_slice(&u64be(index));
    aad.push(if last { 1 } else { 0 });
    aad
}

fn build_header(
    chunk_size: usize,
    total_size: u64,
    real_size: u64,
    flags: u32,
    name: &[u8],
) -> Result<Vec<u8>> {
    if name.len() > u16::MAX as usize {
        return Err(Error::Range);
    }
    let mut out = Vec::with_capacity(HEADER_PLAIN_BYTES + 2 + name.len());
    out.push(1);
    out.push(1);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&u32be(chunk_size as u32));
    out.extend_from_slice(&u64be(total_size));
    out.extend_from_slice(&u64be(real_size));
    out.extend_from_slice(&u32be(flags));
    out.extend_from_slice(&u16be(name.len() as u16));
    out.extend_from_slice(name);
    Ok(out)
}

fn parse_header(plain: &[u8]) -> Result<Header> {
    if plain.len() < HEADER_PLAIN_BYTES {
        return Err(Error::Malformed);
    }
    let version = plain[0];
    if version != 1 {
        return Err(Error::Malformed);
    }
    if plain[1] != 1 {
        return Err(Error::Malformed);
    }
    let chunk_size = read_u32(plain, 4) as usize;
    let total_size = read_u64(plain, 8);
    let real_size = read_u64(plain, 16);
    let flags = read_u32(plain, 24);
    let name_len = u16::from_be_bytes([plain[28], plain[29]]) as usize;
    if plain.len() < HEADER_PLAIN_BYTES + name_len {
        return Err(Error::Truncated);
    }
    if chunk_size == 0 || chunk_size > 64 * 1024 * 1024 || real_size > total_size {
        return Err(Error::Malformed);
    }
    Ok(Header {
        version,
        suite: plain[1],
        chunk_size,
        total_size,
        real_size,
        flags,
        name: plain[HEADER_PLAIN_BYTES..HEADER_PLAIN_BYTES + name_len].to_vec(),
    })
}

pub fn encrypt_bytes(
    pt: &[u8],
    master: &[u8],
    chunk_size: usize,
    pad_to: Option<usize>,
    name: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encrypt_stream(&mut Cursor::new(pt), pt.len() as u64, &mut out, master, chunk_size, pad_to, name)?;
    Ok(out)
}

pub fn decrypt_bytes(ct: &[u8], master: &[u8]) -> Result<(Vec<u8>, Header)> {
    let mut out = Vec::new();
    let header = decrypt_stream(&mut Cursor::new(ct), &mut out, master)?;
    Ok((out, header))
}

pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    source_len: u64,
    writer: &mut W,
    master: &[u8],
    chunk_size: usize,
    pad_to: Option<usize>,
    name: &[u8],
) -> Result<Meta> {
    if chunk_size == 0 {
        return Err(Error::Range);
    }
    let total = match pad_to {
        Some(m) => {
            if source_len > usize::MAX as u64 {
                return Err(Error::Range);
            }
            padme(source_len as usize, m)? as u64
        }
        None => source_len,
    };
    if total < source_len {
        return Err(Error::Range);
    }
    let key = SealKey::new(master)?;
    let salt: [u8; 16] = crate::util::random_array();
    writer.write_all(&salt).map_err(|_| Error::Malformed)?;

    let header = build_header(chunk_size, total, source_len, 0, name)?;
    let header_env = key.seal_random(&header, LABEL_HEADER)?;
    writer.write_all(&u32be(header_env.len() as u32)).map_err(|_| Error::Malformed)?;
    writer.write_all(&header_env).map_err(|_| Error::Malformed)?;

    let chunks = ((total + chunk_size as u64 - 1) / chunk_size as u64).max(1);
    let mut buf = vec![0u8; chunk_size];
    let mut made: u64 = 0;
    for i in 0..chunks {
        let want = chunk_size.min((total - i * chunk_size as u64) as usize);
        let real = chunk_size.min(source_len.saturating_sub(i * chunk_size as u64) as usize);
        let mut filled = 0usize;
        while filled < real {
            let n = reader.read(&mut buf[filled..real]).map_err(|_| Error::Malformed)?;
            if n == 0 {
                return Err(Error::Truncated);
            }
            filled += n;
        }
        if filled < want {
            getrandom::getrandom(&mut buf[filled..want]).map_err(|_| Error::Malformed)?;
        }
        let last = i + 1 == chunks;
        let env = key.seal_random(&buf[..want], &chunk_aad(i, last))?;
        writer.write_all(&u32be(env.len() as u32)).map_err(|_| Error::Malformed)?;
        writer.write_all(&env).map_err(|_| Error::Malformed)?;
        made += want as u64;
    }
    Ok(Meta { bytes_in: source_len, bytes_out: total, chunks, total: made })
}

pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    master: &[u8],
) -> Result<Header> {
    let mut salt = [0u8; 16];
    reader.read_exact(&mut salt).map_err(|_| Error::Truncated)?;
    let mut lenb = [0u8; 4];
    reader.read_exact(&mut lenb).map_err(|_| Error::Truncated)?;
    let header_len = u32::from_be_bytes(lenb) as usize;
    if header_len < 80 || header_len > 1 << 20 {
        return Err(Error::Truncated);
    }
    let mut header_env = vec![0u8; header_len];
    reader.read_exact(&mut header_env).map_err(|_| Error::Truncated)?;
    let key = SealKey::new(master)?;
    let header = parse_header(&key.open(&header_env, LABEL_HEADER, false)?)?;

    let mut produced: u64 = 0;
    let mut written: u64 = 0;
    let mut index: u64 = 0;
    let mut saw_final = false;
    loop {
        let mut lenb = [0u8; 4];
        match reader.read_exact(&mut lenb) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(_) => return Err(Error::Malformed),
        }
        let len = u32::from_be_bytes(lenb) as usize;
        if len < 80 || len > 64 * 1024 * 1024 {
            return Err(Error::Truncated);
        }
        let mut env = vec![0u8; len];
        reader.read_exact(&mut env).map_err(|_| Error::Truncated)?;
        let remaining = header.total_size.saturating_sub(produced);
        let last = remaining <= header.chunk_size as u64;
        let plain = key.open(&env, &chunk_aad(index, last), false)?;
        produced += plain.len() as u64;
        if produced > header.total_size {
            return Err(Error::Malformed);
        }
        let take = ((header.real_size - written) as usize).min(plain.len());
        if take > 0 {
            writer.write_all(&plain[..take]).map_err(|_| Error::Malformed)?;
            written += take as u64;
        }
        index += 1;
        if last {
            saw_final = true;
            break;
        }
    }
    if !saw_final || produced != header.total_size || written != header.real_size {
        return Err(Error::Truncated);
    }
    Ok(header)
}

fn temp_sibling(dst: &Path) -> PathBuf {
    let mut r = [0u8; 8];
    let _ = getrandom::getrandom(&mut r);
    let suffix = u64::from_le_bytes(r);
    let name = dst
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("vanta");
    dst.with_file_name(format!(".{}.vanta-tmp-{:016x}", name, suffix))
}

pub fn encrypt_file(
    src: &Path,
    dst: &Path,
    master: &[u8],
    chunk_size: usize,
    pad_to: Option<usize>,
    name: &[u8],
) -> Result<Meta> {
    let mut input = File::open(src).map_err(|_| Error::Malformed)?;
    let size = input.metadata().map_err(|_| Error::Malformed)?.len();
    let tmp = temp_sibling(dst);
    let result = (|| -> Result<Meta> {
        let mut output = File::create(&tmp).map_err(|_| Error::Malformed)?;
        let meta = encrypt_stream(&mut input, size, &mut output, master, chunk_size, pad_to, name)?;
        output.sync_all().map_err(|_| Error::Malformed)?;
        Ok(meta)
    })();
    match result {
        Ok(meta) => {
            fs::rename(&tmp, dst).map_err(|_| Error::Malformed)?;
            Ok(meta)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub fn decrypt_file(src: &Path, dst: &Path, master: &[u8]) -> Result<Header> {
    let mut input = File::open(src).map_err(|_| Error::Malformed)?;
    let tmp = temp_sibling(dst);
    let result = (|| -> Result<Header> {
        let mut output = File::create(&tmp).map_err(|_| Error::Malformed)?;
        let header = decrypt_stream(&mut input, &mut output, master)?;
        output.sync_all().map_err(|_| Error::Malformed)?;
        Ok(header)
    })();
    match result {
        Ok(header) => {
            fs::rename(&tmp, dst).map_err(|_| Error::Malformed)?;
            Ok(header)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}
