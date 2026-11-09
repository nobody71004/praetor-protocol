# VANTA/1 over TCP

`src/transport.js` (exported as `@vanta/protocol/transport`) carries a VANTA
session over a Node TCP socket.

## Framing

```text
handshake:  u32(len) || handshake-message       (length-framed)
stream:     cellSize + 80 bytes, repeated        (fixed cells, no lengths)
```

Handshake messages are `clientInit` (2368 B), `serverRespond` (1184 B) and the
32-byte client confirmation. After that, both directions are fixed-size VSEAL
cells. The receiver reads exactly `cellSize + 80` bytes at a time, so there is
no record-length field to fingerprint.

## Server

```js
import { createVantaServer } from '@vanta/protocol/transport';
import { generateServerKeypair } from '@vanta/protocol';

const keys = generateServerKeypair();
const server = await createVantaServer({
  serverKeys: keys,
  host: '127.0.0.1',
  port: 9443,
  cellSize: 1024,
  onConnection(conn) {
    conn.on('message', (data) => conn.send(data));
    conn.on('error', () => {});
  },
});
console.log(server.address.port);
```

`onConnection` runs before the receive pump starts, so listeners attached there
cannot miss the first cell. `server.close()` destroys remaining sockets and
waits for the listener to close.

## Client

```js
import { connectVanta } from '@vanta/protocol/transport';

const conn = await connectVanta({
  host: '127.0.0.1',
  port: 9443,
  serverPublicKey: pinnedServerPublicKey, // 1216 bytes, authenticated out of band
  cellSize: 1024,
});
conn.on('message', (data) => console.log(data.length));
await conn.send(Buffer.from('hello'));
conn.close();
```

The server public key **must be pinned** (configuration, DNS-based key
transparency, or a prior approval flow). The handshake proves possession of the
secret key; it does not discover trust.

## Configuration rules

* Both sides must use the same `cellSize` and ratchet interval. A mismatch
  fails authentication rather than silently downgrading; the cell size is a
  local policy decision, not negotiated.
* `maxMessageBytes` bounds reassembly memory. The default is 64 MiB.
* `send()` awaits the socket write callback for backpressure. A slow peer
  slows the sender instead of growing an unbounded queue.
* `sendPadding()` emits a cover cell; call it on a schedule for constant-rate
  traffic.

## What this does not do

* No TLS. VANTA protects the payload and its framing, but a network observer can
  still see IP addresses, ports, timing and total bytes. Add TLS/QUIC or a
  cover-traffic schedule if that metadata is in scope.
* No PKI, ALPN, 0-RTT, connection migration or multiplexing.
* No proof-of-work gate in the adapter. Put `AdmissionGate` in front of
  `createVantaServer` if handshake floods are a concern.
* TCP only. A QUIC adapter is a separate exercise; the cell layer is
  transport-agnostic.
