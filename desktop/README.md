# PRAETOR Command

PRAETOR Command is a Windows desktop control plane built with Electron, React, and a local
[MCP](https://modelcontextprotocol.io/) server. It combines a PRAETOR/1 crypto-profile manager,
header-art slots, cursor-reactive visuals, a tool catalog, and an agent fabric.

> **Data plane:** connecting a PSEAL profile opens a real PRAETOR/1 TCP session to the
> configured egress host, multiplexes TCP streams over it, and points the Windows system proxy at a local
> SOCKS5 listener while the session is up. Traffic counters, handshake time, and the session log
> come from that transport. The MCP server, tool execution, audit log, and agent loop are local.

## Run

```bash
cd desktop
npm install
npm run dev
```

`npm run dev` builds the MCP bundles, starts Vite on `127.0.0.1:5173`, and launches Electron.
For the production renderer without packaging:

```bash
npm run build
npm start
```

## Build the EXE

```bash
cd desktop
npm run icon       # regenerate build/icon.ico (only needed after changing the mark)
npm run dist
```

The portable application is written to `release/PRAETOR-Command-1.0.1.exe`. It is unsigned, so
Windows SmartScreen may show a warning.

If electron-builder cannot reach GitHub for its Windows toolsets, use a mirror:

```bash
ELECTRON_BUILDER_BINARIES_MIRROR="https://npmmirror.com/mirrors/electron-builder-binaries/" \
  npx electron-builder --win portable
```

## PRAETOR crypto profiles

Profiles use the PRAETOR/1 protocol rather than WireGuard. Each profile stores only the client-side
configuration needed to reach a server:

- `protocol`: `PRAETOR/1` with the hybrid X25519 + ML-KEM-768 handshake.
- `suite`: `PSEAL` (default), `FAST`, `BOLT`, or `PMARINE`. All four connect over the PSEAL
  transport today; FAST, BOLT and PMARINE are routing presets until their separate channels are
  negotiated.
- `endpoint`: TCP `host:port`; the reference transport uses port `9443`.
- `cellSize`: fixed framing size. Both ends must use the same value; wire cells add 80 bytes.
- `serverPublicKey`: the pinned 1,216-byte X-Wing public key.

The Overview page switches the active profile. Switching while a session is active closes the
previous session and starts a new PRAETOR handshake. Client X-Wing keypairs are ephemeral per
handshake and are never written to a profile.

The seeded **Nexus PSEAL** profile pins a reference server's 1,216-byte X-Wing public key and points at
its bundled endpoint. **Nexus FAST**, **Nexus BOLT** and **Nexus PMARINE** also connect
successfully, using the PSEAL transport that the current egress implements; the app reports `PSEAL`
as the negotiated suite and labels the requested profile in Activity. The PMARINE preset is
marked experimental; the Rust `PmarineChannel` is not negotiated by the desktop client yet. To use
your own exit, generate a keypair and deploy the
server bundle with [`server/README.md`](server/README.md), then update the profile endpoint and pinned
public key.

## Data plane

`electron/praetor-tunnel.cjs` is a bundled PRAETOR/1 client. On connect the main process:

1. Opens the pinned X-Wing session to the profile's TCP endpoint.
2. Starts a SOCKS5/SOCKS4 listener on stable loopback port `17890`, falling back to an ephemeral port
   only if `17890` is already occupied.
3. Sets `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` to
   `socks=127.0.0.1:<port>`, adds the `<local>` bypass, and refreshes WinINET.
4. Multiplexes SOCKS5/SOCKS4 CONNECT streams as PRAETOR `CONNECT`/`DATA`/`CLOSE` frames and counts
   the bytes that actually cross the session.

Disconnecting, switching profiles, deleting the active profile, or quitting restores the previous
system-proxy values. The pre-PRAETOR values and a managed-proxy marker are persisted; if the app is
killed while connected, the next launch restores direct access before opening the window. DNS is
resolved by the exit, not locally. This is a TCP proxy, not a TUN/IP tunnel: browsers and applications
that honor the Windows system proxy use it, while apps with their own proxy configuration or raw
sockets bypass it.

The server side is the self-contained Node bundle in `server/`. It pins its private X-Wing key,
listens on TCP `9443`, and only allows PSEAL. Ingress is a single `nftables` allowance maintained by
`praetor-ingress.service` after Nexus Shield rebuilds its ruleset.

## MCP and external agents

Open **Agent Fabric** in the app to run the built-in diagnostic, copy the generated MCP config, or
launch an agent. The 36 tools cover system information, screen capture, mouse and keyboard input,
application control, filesystem access, shell commands, developer workflows, clipboard, notifications,
processes, and policy inspection.

The generated config is at `%APPDATA%\PRAETOR Command\mcp-config.json`. It points at a detected system
Node runtime when one is available so the config remains valid after the app closes. Install Node.js
20+ if you want external MCP clients to connect. The MCP bundles themselves live in
`%APPDATA%\PRAETOR Command\mcp\` and in the app's `resources\mcp` directory.

Example agent runtimes that can use the config:

```json
{
  "mcpServers": {
    "praetor-computer-use": {
      "command": "C:\\Program Files\\nodejs\\node.exe",
      "args": ["C:\\Users\\<you>\\AppData\\Roaming\\PRAETOR Command\\mcp\\server.mjs"],
      "env": {
        "PRAETOR_MCP_ROOTS": "C:\\Users\\<you>",
        "PRAETOR_MCP_AUDIT": "C:\\Users\\<you>\\AppData\\Roaming\\PRAETOR Command\\audit.jsonl",
        "PRAETOR_MCP_ALLOW_WRITES": "1",
        "PRAETOR_MCP_ALLOW_SHELL": "0",
        "PRAETOR_MCP_ALLOW_FULL": "0"
      }
    }
  }
}
```

The diagnostic command is also available from a terminal:

```bash
npm run mcp:test
```

### Safety model

- MCP roots are allowlisted by the app; filesystem tools cannot escape them.
- Shell and unrestricted full-control tools stay disabled unless **Full control** is enabled in
  Settings or Agent Fabric. Keep it off until you specifically need destructive or system-wide actions.
- Every tool call is appended to `%APPDATA%\PRAETOR Command\audit.jsonl`, with arguments redacted in
  the activity feed where applicable.
- Agent model API keys are kept in memory for the run only and passed to the child through its
  environment. They are not written to the app's state file.
- The renderer has no Node integration and uses a narrow context-isolated preload bridge. External
  links are opened only after an HTTP(S) check.

## Optional model agent

The optional agent loop talks to any OpenAI-compatible chat-completions endpoint. Set the base URL and
model in Agent Fabric, then enter an API key for the run. The default endpoint is
`https://api.openai.com/v1`; point it at another compatible provider if desired. The diagnostic works
without an API key.

## Verification performed

- Renderer production build and CSS class audit pass.
- The profile store is exercised for PRAETOR defaults, schema migration, and profile save/load.
- The PRAETOR client completed a real handshake against a self-hosted test exit (199 ms);
  `ipinfo.io`, `ipify`, and `speedtest.net` returned through the SOCKS5 egress with that exit's
  public IP.
- The MCP diagnostic passes under both Node and the packaged Electron runtime: 36 tools, 7/7 steps.
- The portable EXE launches the packaged app, stages its MCP runtime, and reports the Agent Fabric page
  as `MCP ONLINE` in guarded mode.
- The generated external config was tested with a direct MCP JSON-RPC handshake.

## Project layout

```
electron/            main process, preload bridge, local store
mcp/                 policy, tools, stdio server, pipeline, optional model loop
scripts/             esbuild MCP bundler and icon generator
src/                 React renderer, pages, components, styles
dist/                built renderer
mcp-dist/            esbuild-bundled MCP runtime
release/             packaged EXE and unpacked build
```
