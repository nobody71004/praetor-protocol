#!/usr/bin/env node
// PRAETOR/1 egress data-plane server.
//
// Deploy this on the exit host. It accepts PRAETOR sessions and forwards the
// multiplexed TCP streams to their targets. No TUN device, root network
// namespace or IP forwarding is required: outbound sockets are ordinary host
// connections made by this process.
import { readFileSync } from 'node:fs';
import { createEgressServer } from '../src/egress.js';

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

const keyPath = arg('key', process.env.PRAETOR_EGRESS_KEY || '/opt/praetor-egress/server.key');
const host = arg('host', process.env.PRAETOR_EGRESS_HOST || '0.0.0.0');
const port = Number(arg('port', process.env.PRAETOR_EGRESS_PORT || '9443'));
const cellSize = Number(arg('cell-size', process.env.PRAETOR_CELL_SIZE || '1024'));

let secretKey;
try {
  secretKey = Buffer.from(readFileSync(keyPath, 'utf8').trim(), 'base64');
} catch (err) {
  console.error(`cannot read server key ${keyPath}: ${err.message}`);
  process.exit(1);
}
if (secretKey.length !== 2432) {
  console.error(`server key must be 2432 bytes, got ${secretKey.length}`);
  process.exit(1);
}

const server = await createEgressServer({
  serverKeys: { secretKey },
  host,
  port,
  cellSize,
  onLog: (message) => console.log(`[${new Date().toISOString()}] ${message}`),
});

console.log(
  JSON.stringify({
    ok: true,
    protocol: 'PRAETOR/1',
    suite: 'PSEAL',
    address: server.address,
    cellSize,
  }),
);

const shutdown = async () => {
  await server.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
