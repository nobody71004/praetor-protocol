// PRAETOR/1 Rust egress server.
//
// Accepts PRAETOR sessions and forwards their multiplexed TCP streams to
// arbitrary targets. Wire-compatible with praetor/bin/praetor-egress.js and the
// desktop client's egress frames. No TUN device, root network namespace or IP
// forwarding is required: outbound sockets are ordinary host connections.
//
// Usage:
//   praetor-egress --key server.key --host 0.0.0.0 --port 9443
//
// The key file is the base64 X-Wing secret key (2,432 decoded bytes).

use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::TcpListener;
use std::process::ExitCode;

use praetor::egress::{serve, EgressConfig};
use praetor::xwing::{self, XWING_PK_BYTES, XWING_SK_BYTES};

struct Args {
    flags: HashMap<String, String>,
}

impl Args {
    fn parse() -> Self {
        let mut flags = HashMap::new();
        let mut it = env::args().skip(1);
        while let Some(arg) = it.next() {
            if let Some(name) = arg.strip_prefix("--") {
                if let Some(eq) = name.find('=') {
                    flags.insert(name[..eq].to_string(), name[eq + 1..].to_string());
                } else {
                    flags.insert(name.to_string(), it.next().unwrap_or_default());
                }
            }
        }
        Self { flags }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(String::as_str)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("praetor-egress: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let key_path = args
        .get("key")
        .map(str::to_string)
        .or_else(|| env::var("PRAETOR_EGRESS_KEY").ok())
        .unwrap_or_else(|| "/opt/praetor-egress/server.key".to_string());
    let text = fs::read_to_string(&key_path)
        .map_err(|err| format!("cannot read server key {key_path}: {err}"))?;
    let secret_key = decode_base64(text.trim())
        .ok_or_else(|| format!("server key {key_path} is not valid base64"))?;
    if secret_key.len() != XWING_SK_BYTES {
        return Err(format!(
            "server key must be {XWING_SK_BYTES} decoded bytes, got {}",
            secret_key.len()
        ));
    }
    let public_key = xwing::public_from_secret(&secret_key)
        .map_err(|err| format!("invalid server key: {}", err.code()))?;
    if public_key.len() != XWING_PK_BYTES {
        return Err(format!(
            "derived public key must be {XWING_PK_BYTES} bytes, got {}",
            public_key.len()
        ));
    }

    let host = args.get("host").unwrap_or("0.0.0.0");
    let port = args
        .get("port")
        .map(|value| value.parse::<u16>())
        .transpose()
        .map_err(|_| "port must be 1-65535".to_string())?
        .unwrap_or(9443);
    let cell_size = args
        .get("cell-size")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| "cell-size must be an integer".to_string())?
        .unwrap_or(1024);
    let max_message_mib = args
        .get("max-message-mib")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| "max-message-mib must be an integer".to_string())?
        .unwrap_or(64);
    let connect_timeout_ms = args
        .get("connect-timeout-ms")
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| "connect-timeout-ms must be an integer".to_string())?
        .unwrap_or(10_000);
    let quiet = args.flags.contains_key("quiet");

    let listener = TcpListener::bind((host, port))
        .map_err(|err| format!("cannot bind {host}:{port}: {err}"))?;
    let address = listener
        .local_addr()
        .map_err(|err| format!("cannot read listener address: {err}"))?;

    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "implementation": "rust",
            "protocol": "PRAETOR/1",
            "suite": "PSEAL",
            "address": address.to_string(),
            "cell_size": cell_size,
        })
    );

    let config = EgressConfig {
        cell_size,
        max_message_bytes: max_message_mib.saturating_mul(1024 * 1024),
        connect_timeout: std::time::Duration::from_millis(connect_timeout_ms),
        log: !quiet,
    };
    serve(listener, public_key, secret_key, config)
        .map_err(|err| format!("egress server failed: {err}"))
}

/// Decode standard base64 with optional whitespace and padding.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}
