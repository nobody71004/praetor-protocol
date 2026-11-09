#!/usr/bin/env bash
# Cargo wrapper: prefer the project-local toolchain, fall back to system cargo.
# Nothing is installed system-wide by this script.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LOCAL_CARGO="$ROOT/.toolchain/cargo/bin/cargo"
if [ -x "${LOCAL_CARGO}.exe" ]; then
  LOCAL_CARGO="${LOCAL_CARGO}.exe"
fi

if [ -x "$LOCAL_CARGO" ]; then
  export RUSTUP_HOME="$(cygpath -w "$ROOT/.toolchain/rustup" 2>/dev/null || echo "$ROOT/.toolchain/rustup")"
  export CARGO_HOME="$(cygpath -w "$ROOT/.toolchain/cargo" 2>/dev/null || echo "$ROOT/.toolchain/cargo")"
  exec "$LOCAL_CARGO" "$@"
fi

exec cargo "$@"
