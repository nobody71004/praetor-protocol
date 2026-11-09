use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use praetor::aead::{SealKey, OVERHEAD};
use praetor::container;
use praetor::error::{Error, Result};
use praetor::padme::padme;
use praetor::pmarine::PmarineKey;
use praetor::util::u32be;

fn usage() {
    eprintln!(
        "PRAETOR/1 (Rust)\n\n\
         praetor keygen --out FILE            write a 32-byte key (0600)\n\
         praetor seal --key FILE [--in F] [--out F] [--aad S] [--pad M]\n\
         praetor open --key FILE [--in F] [--out F] [--aad S] [--pad]\n\
         praetor encrypt --key FILE --in F --out F [--chunk N] [--pad M]\n\
         praetor decrypt --key FILE --in F --out F\n\
         praetor bench\n\
         praetor selftest\n\
         praetor manifest\n"
    );
}

struct Args {
    cmd: String,
    flags: std::collections::HashMap<String, String>,
}

fn parse() -> Args {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_else(|| "help".into());
    let mut flags = std::collections::HashMap::new();
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
            if let Some(eq) = name.find('=') {
                flags.insert(name[..eq].to_string(), name[eq + 1..].to_string());
            } else {
                let value = it.next().unwrap_or_default();
                flags.insert(name.to_string(), value);
            }
        }
    }
    Args { cmd, flags }
}

fn load_key(args: &Args) -> Result<[u8; 32]> {
    let path = args
        .flags
        .get("key")
        .ok_or(Error::Key)?;
    let raw = fs::read(path).map_err(|_| Error::Key)?;
    if raw.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        return Ok(k);
    }
    let text = String::from_utf8(raw).map_err(|_| Error::Key)?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| Error::Key)?;
    let b64 = v.get("key").and_then(|x| x.as_str()).ok_or(Error::Key)?;
    decode_b64(b64)
}

fn decode_b64(s: &str) -> Result<[u8; 32]> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let idx = T.iter().position(|&x| x == c).ok_or(Error::Key)? as u32;
        buf = (buf << 6) | idx;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    if out.len() != 32 {
        return Err(Error::Key);
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    Ok(k)
}

fn read_input(args: &Args) -> Result<Vec<u8>> {
    match args.flags.get("in") {
        Some(p) => fs::read(p).map_err(|_| Error::Malformed),
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf).map_err(|_| Error::Malformed)?;
            Ok(buf)
        }
    }
}

fn write_output(args: &Args, data: &[u8]) -> Result<()> {
    match args.flags.get("out") {
        Some(p) => fs::write(p, data).map_err(|_| Error::Malformed),
        None => {
            std::io::stdout().write_all(data).map_err(|_| Error::Malformed)?;
            Ok(())
        }
    }
}

fn flag_usize(args: &Args, name: &str) -> Option<usize> {
    args.flags.get(name).and_then(|v| v.parse().ok())
}

fn main() -> ExitCode {
    let args = parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("praetor: {}", e.code());
            ExitCode::from(2)
        }
    }
}

fn run(args: &Args) -> Result<()> {
    match args.cmd.as_str() {
        "keygen" => {
            let key: [u8; 32] = praetor::util::random_array();
            let out = args.flags.get("out").cloned().unwrap_or_else(|| "praetor.key".into());
            let b64 = encode_b64(&key);
            let json = format!("{{\"version\":1,\"suite\":\"PRAETOR/1\",\"key\":\"{}\"}}\n", b64);
            fs::write(&out, json).map_err(|_| Error::Malformed)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&out, fs::Permissions::from_mode(0o600));
            }
            eprintln!("wrote {} (32-byte master key)", out);
            Ok(())
        }
        "seal" => {
            let key = load_key(args)?;
            let mut pt = read_input(args)?;
            if let Some(m) = flag_usize(args, "pad") {
                let target = padme(pt.len() + 4, m)?;
                let mut body = Vec::with_capacity(target);
                body.extend_from_slice(&u32be(pt.len() as u32));
                body.extend_from_slice(&pt);
                let mut pad = vec![0u8; target - body.len()];
                getrandom::getrandom(&mut pad).map_err(|_| Error::Malformed)?;
                body.extend_from_slice(&pad);
                pt = body;
            }
            let aad = args.flags.get("aad").cloned().unwrap_or_default();
            let env = SealKey::new(&key)?.seal_random(&pt, aad.as_bytes())?;
            write_output(args, &env)
        }
        "open" => {
            let key = load_key(args)?;
            let env = read_input(args)?;
            let aad = args.flags.get("aad").cloned().unwrap_or_default();
            let mut pt = SealKey::new(&key)?.open(&env, aad.as_bytes(), false)?;
            if args.flags.contains_key("pad") {
                if pt.len() < 4 {
                    return Err(Error::Malformed);
                }
                let n = u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]) as usize;
                if n > pt.len() - 4 {
                    return Err(Error::Malformed);
                }
                pt = pt[4..4 + n].to_vec();
            }
            write_output(args, &pt)
        }
        "encrypt" => {
            let key = load_key(args)?;
            let input = args.flags.get("in").ok_or(Error::Malformed).cloned()?;
            let output = args.flags.get("out").ok_or(Error::Malformed).cloned()?;
            let chunk = flag_usize(args, "chunk").unwrap_or(container::DEFAULT_CHUNK_SIZE);
            let meta = container::encrypt_file(
                &PathBuf::from(&input),
                &PathBuf::from(&output),
                &key,
                chunk,
                flag_usize(args, "pad"),
                b"",
            )?;
            eprintln!("encrypted {} -> {} ({} chunks)", input, output, meta.chunks);
            Ok(())
        }
        "decrypt" => {
            let key = load_key(args)?;
            let input = args.flags.get("in").ok_or(Error::Malformed).cloned()?;
            let output = args.flags.get("out").ok_or(Error::Malformed).cloned()?;
            let header =
                container::decrypt_file(&PathBuf::from(&input), &PathBuf::from(&output), &key)?;
            eprintln!("decrypted {} bytes -> {}", header.total_size, output);
            Ok(())
        }
        "bench" => bench(),
        "selftest" => selftest(),
        "manifest" => {
            let m = serde_json::json!({
                "protocol": "PRAETOR/1",
                "implementation": "rust",
                "version": praetor::VERSION,
                "aead": "PSEAL/1",
                "overhead": OVERHEAD,
                "status": "reference implementation, not audited"
            });
            println!("{}", serde_json::to_string_pretty(&m).unwrap());
            Ok(())
        }
        _ => {
            usage();
            Ok(())
        }
    }
}

fn bench() -> Result<()> {
    use std::hint::black_box;
    use std::time::Instant;

    let key = [7u8; 32];
    let seal = SealKey::new(&key)?;
    println!("PRAETOR/1 Rust benchmark (release build)");
    for &size in &[1024usize, 65_536, 1_048_576] {
        let pt = vec![0u8; size];
        let iters = if size >= 1_048_576 { 64 } else { 1024 };
        let env = seal.seal_random(&pt, b"bench")?;

        let t = Instant::now();
        for _ in 0..iters {
            black_box(seal.seal_random(black_box(&pt), b"bench")?);
        }
        let seal_s = t.elapsed().as_secs_f64();

        let t = Instant::now();
        for _ in 0..iters {
            black_box(seal.open(black_box(&env), b"bench", false)?);
        }
        let open_s = t.elapsed().as_secs_f64();
        let mib = (size * iters) as f64 / (1024.0 * 1024.0);
        println!(
            "pseal {:>8} B   seal {:8.1} MiB/s   open {:8.1} MiB/s",
            size,
            mib / seal_s,
            mib / open_s
        );
    }

    let (pk, sk) = praetor::xwing::keygen();
    let kem_iters = 200;
    let (ct, _) = praetor::xwing::encapsulate(&pk)?;
    let t = Instant::now();
    for _ in 0..kem_iters {
        black_box(praetor::xwing::decapsulate(black_box(&ct), black_box(&sk))?);
    }
    println!("kem.decaps     {:8.0} ops/s", kem_iters as f64 / t.elapsed().as_secs_f64());

    let hs_iters = 50;
    let t = Instant::now();
    for _ in 0..hs_iters {
        let (c1, mut cs) = praetor::handshake::client_init(&pk)?;
        let (s1, mut ss) = praetor::handshake::server_respond(&sk, &c1)?;
        let (confirm, _) = praetor::handshake::client_finish(&mut cs, &s1)?;
        black_box(praetor::handshake::server_finish(&mut ss, &confirm)?);
    }
    println!(
        "handshake      {:8.0} ops/s",
        hs_iters as f64 / t.elapsed().as_secs_f64()
    );
    Ok(())
}

fn selftest() -> Result<()> {
    let key: [u8; 32] = praetor::util::random_array();
    let sk = SealKey::new(&key)?;
    let pt = vec![7u8; 4096];
    let env = sk.seal_random(&pt, b"selftest")?;
    let out = sk.open(&env, b"selftest", false)?;
    assert_eq!(out, pt, "pseal roundtrip");
    let mut bad = env.clone();
    bad[100] ^= 1;
    assert!(sk.open(&bad, b"selftest", false).is_err(), "tamper");

    let pm = PmarineKey::new(&key)?;
    let pm_env = pm.seal_random(&pt, b"selftest")?;
    assert_eq!(pm.open(&pm_env, b"selftest", false)?, pt, "pmarine roundtrip");
    let mut pm_bad = pm_env.clone();
    pm_bad[100] ^= 1;
    assert!(pm.open(&pm_bad, b"selftest", false).is_err(), "pmarine tamper");

    let ct = container::encrypt_bytes(&pt, &key, 1024, None, b"")?;
    let (back, _) = container::decrypt_bytes(&ct, &key)?;
    assert_eq!(back, pt, "container roundtrip");
    println!("selftest: PASS (pseal, pmarine, container)");
    Ok(())
}

fn encode_b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}
