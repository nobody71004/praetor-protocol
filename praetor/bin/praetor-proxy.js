#!/usr/bin/env node
// PRAETOR/1 local SOCKS5 egress proxy.
//
// Usage:
//   praetor-proxy --host 104.251.218.227 --port 9443 \
//     --server-key server.pub --listen 1080
//
// The pinned server public key is read as base64 from --server-key.
import { readFileSync } from 'node:fs';
import { startSocksProxy } from '../src/egress-client.js';

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

const host = arg('host', process.env.PRAETOR_EGRESS_HOST || '127.0.0.1');
const port = Number(arg('port', process.env.PRAETOR_EGRESS_PORT || '9443'));
const keyPath = arg('server-key', process.env.PRAETOR_SERVER_PUBLIC_KEY_FILE);
const listenHost = arg('listen-host', process.env.PRAETOR_PROXY_HOST || '127.0.0.1');
const listenPort = Number(arg('listen', process.env.PRAETOR_PROXY_PORT || '1080'));
const cellSize = Number(arg('cell-size', process.env.PRAETOR_CELL_SIZE || '1024'));

if (!keyPath) {
  console.error('--server-key <base64 public key file> is required');
  process.exit(1);
}
const serverPublicKey = Buffer.from(readFileSync(keyPath, 'utf8').trim(), 'base64');
if (serverPublicKey.length !== 1216) {
  console.error(`server public key must be 1216 bytes, got ${serverPublicKey.length}`);
  process.exit(1);
}

let proxy;
try {
  proxy = await startSocksProxy({
    serverPublicKey,
    host,
    port,
    cellSize,
    proxyHost: listenHost,
    proxyPort: listenPort,
    onTraffic: () => {},
    onLog: (message) => console.log(`[${new Date().toISOString()}] ${message}`),
  });
} catch (err) {
  console.error(`PRAETOR handshake failed: ${err.message}`);
  process.exit(1);
}

console.log(
  JSON.stringify({
    ok: true,
    protocol: 'PRAETOR/1',
    proxy: `socks5://${listenHost}:${proxy.port}`,
    handshakeMs: proxy.handshakeMs,
    sessionId: proxy.sessionId.toString('hex'),
  }),
);

const shutdown = () => {
  proxy.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
