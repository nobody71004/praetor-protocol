# PRAETOR egress server

This directory contains the Dallas exit for PRAETOR Command. The server is a
self-contained Node 22 bundle: it terminates the PRAETOR/1 session, opens ordinary
outbound TCP sockets for each multiplexed `CONNECT`, and never creates a TUN
device or changes IP forwarding.

## Files

| File | Purpose |
| --- | --- |
| `praetor-egress.service` | Runs the Node bundle as root on TCP `9443`. |
| `praetor-ingress.service` | Re-adds the single nftables allow after Nexus Shield rebuilds its ruleset. |
| `praetor-ingress-rule.sh` | Inserts `tcp dport 9443 accept comment "praetor:egress"` if absent. |
| `deploy.sh` | Copies the bundle, key, units and script to the host, then enables both units. |
| `keys/praetor-server.key` | Base64 X-Wing secret key (2,432 decoded bytes). Never commit or print it. |
| `keys/praetor-server.pub` | Base64 X-Wing public key (1,216 decoded bytes), pinned by clients. |
| `server-info.json` | Endpoint and public-key metadata used to seed profiles. |

## Generate a replacement keypair

Run from the `praetor` source checkout:

```bash
node --input-type=module <<'NODE'
import { writeFileSync } from 'node:fs';
import { generateServerKeypair } from './src/index.js';
const { publicKey, secretKey } = generateServerKeypair();
writeFileSync('server.key', `${secretKey.toString('base64')}\n`, { mode: 0o600 });
writeFileSync('server.pub', `${publicKey.toString('base64')}\n`);
NODE
```

Keep `server.key` root-readable only. Put the public key in each client profile,
or update `src/lib/praetor.js` / `electron/store.cjs` defaults before rebuilding
the desktop app.

## Deploy

Build the server bundle from the `praetor` checkout:

```bash
cd praetor
node_modules/.bin/esbuild bin/praetor-egress.js \
  --bundle --platform=node --format=esm --target=node20 \
  --outfile=dist/praetor-egress.mjs
```

Install Node 22 once on the host if it is not already present. The service unit
expects `/opt/praetor-egress/node/bin/node`; adjust `ExecStart` if your runtime is
elsewhere.

From the workspace root:

```bash
bash vanta-repo/desktop/server/deploy.sh
```

The script copies the bundle and key, installs the two units and the ingress
helper, then enables and starts them. It defaults to `root@104.251.218.227` and
`tmp/relay_ed25519`; override with `PRAETOR_EGRESS_SSH` and
`PRAETOR_EGRESS_SSH_KEY`.

Nexus Shield owns `table inet nexus_edge` and regenerates it from
`/etc/nexus-shield/config.json`. `praetor-ingress.service` is `PartOf` the shield
unit, so a shield restart re-runs the oneshot and restores the 9443 allowance.
It refuses to guess if the table is missing.

## Verify

Check the listener and rule on the host:

```bash
systemctl status praetor-egress
ss -lntp | grep 9443
nft list chain inet nexus_edge input | grep praetor
```

Test the real egress from the client machine:

```bash
node praetor/bin/praetor-proxy.js \
  --host 104.251.218.227 --port 9443 \
  --server-key vanta-repo/desktop/server/keys/praetor-server.pub \
  --listen 1080

curl --socks5-hostname 127.0.0.1:1080 https://ipinfo.io/json
```

The response must show `"ip": "104.251.218.227"` and Dallas, Texas.

## Security notes

- The client authenticates the server with the pinned X-Wing key. The server does
  not authenticate individual clients; anyone who knows the public key can use the
  exit. Keep the key distribution private, and add a network allowlist or a
  pre-shared admission check if the host is shared with untrusted users.
- `PSEAL` is the only suite implemented by this JavaScript transport. The desktop
  app rejects `FAST` and `BOLT` connects with a clear error.
- The service runs as root only because the existing host layout uses root for
  the Node install and nftables. The Node process itself does not require root
  once the ingress rule exists; a dedicated unprivileged user is a reasonable
  hardening step.
