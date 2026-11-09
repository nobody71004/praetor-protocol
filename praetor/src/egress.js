// PRAETOR/1 — multiplexed TCP egress over one authenticated stream.
//
// A single PRAETOR session carries many TCP streams. Each message is one
// frame:
//
//   u32 streamId || u8 op || payload
//
//   CONNECT (1)  payload = u16 hostLen || host || u16 port
//   DATA    (2)  payload = opaque bytes, at most MAX_EGRESS_PAYLOAD
//   CLOSE   (3)  payload = empty
//   OK      (4)  server -> client, target connected
//   ERROR   (5)  server -> client, payload = UTF-8 reason
//
// The frame layer runs inside PRAETOR's authenticated fixed cells, so the
// stream id, target and bytes are all encrypted and authenticated. This module
// deliberately does not expose a raw IP tunnel: it is a TCP egress proxy, which
// is enough for a browser and does not require a TUN driver.
import net from 'node:net';
import { Buffer } from 'node:buffer';
import { createPraetorServer } from './transport.js';
import { ERR, assert, toBytes } from './util.js';

export const FRAME_HEADER_BYTES = 5;
export const EGRESS_CONNECT = 1;
export const EGRESS_DATA = 2;
export const EGRESS_CLOSE = 3;
export const EGRESS_OK = 4;
export const EGRESS_ERROR = 5;
export const MAX_EGRESS_PAYLOAD = 32 * 1024;
const MAX_HOST_BYTES = 255;

export function encodeEgressFrame(streamId, op, payload = Buffer.alloc(0)) {
  assert(Number.isInteger(streamId) && streamId >= 0 && streamId <= 0xffffffff, ERR.RANGE, 'bad stream id');
  assert(Number.isInteger(op) && op >= EGRESS_CONNECT && op <= EGRESS_ERROR, ERR.RANGE, 'bad egress op');
  const body = toBytes(payload);
  assert(body.length <= MAX_EGRESS_PAYLOAD, ERR.RANGE, 'egress payload too large');
  const out = Buffer.allocUnsafe(FRAME_HEADER_BYTES + body.length);
  out.writeUInt32BE(streamId >>> 0, 0);
  out[4] = op;
  body.copy(out, FRAME_HEADER_BYTES);
  return out;
}

export function decodeEgressFrame(buffer) {
  const buf = toBytes(buffer);
  assert(buf.length >= FRAME_HEADER_BYTES, ERR.MALFORMED, 'short egress frame');
  assert(buf.length - FRAME_HEADER_BYTES <= MAX_EGRESS_PAYLOAD, ERR.MALFORMED, 'oversized egress frame');
  return {
    streamId: buf.readUInt32BE(0),
    op: buf[4],
    payload: buf.subarray(FRAME_HEADER_BYTES),
  };
}

export function encodeConnectPayload(host, port) {
  const name = Buffer.from(String(host), 'utf8');
  assert(name.length > 0 && name.length <= MAX_HOST_BYTES, ERR.RANGE, 'bad target host');
  assert(Number.isInteger(port) && port > 0 && port <= 65535, ERR.RANGE, 'bad target port');
  const out = Buffer.allocUnsafe(2 + name.length + 2);
  out.writeUInt16BE(name.length, 0);
  name.copy(out, 2);
  out.writeUInt16BE(port, 2 + name.length);
  return out;
}

export function decodeConnectPayload(payload) {
  const buf = toBytes(payload);
  assert(buf.length >= 4, ERR.MALFORMED, 'short connect frame');
  const nameLen = buf.readUInt16BE(0);
  assert(
    nameLen > 0 && nameLen <= MAX_HOST_BYTES && buf.length === 4 + nameLen,
    ERR.MALFORMED,
    'bad connect frame length',
  );
  const host = buf.subarray(2, 2 + nameLen).toString('utf8');
  const port = buf.readUInt16BE(2 + nameLen);
  assert(port > 0, ERR.MALFORMED, 'bad connect port');
  return { host, port };
}

function writeChunks(send, streamId, op, chunk) {
  for (let offset = 0; offset < chunk.length; offset += MAX_EGRESS_PAYLOAD) {
    send(streamId, op, chunk.subarray(offset, offset + MAX_EGRESS_PAYLOAD));
  }
}

function serveConnection(conn, onLog) {
  const streams = new Map();
  let closed = false;
  let sendChain = Promise.resolve();
  let sendFailed = false;

  const close = (reason) => {
    if (closed) return;
    closed = true;
    for (const entry of streams.values()) entry.socket.destroy();
    streams.clear();
    try {
      conn.close();
    } catch {
      /* already gone */
    }
    if (reason) onLog(`connection closed: ${reason}`);
  };

  const send = (streamId, op, payload) => {
    if (closed || sendFailed) return;
    let frame;
    try {
      frame = encodeEgressFrame(streamId, op, payload);
    } catch (err) {
      close(err.message);
      return;
    }
    sendChain = sendChain
      .then(() => conn.send(frame))
      .catch((err) => {
        sendFailed = true;
        close(err.message);
      });
  };

  const finish = (streamId, entry, notify) => {
    if (entry.done) return;
    entry.done = true;
    streams.delete(streamId);
    if (notify && !closed) send(streamId, EGRESS_CLOSE, Buffer.alloc(0));
  };

  const connectTarget = (streamId, payload) => {
    let target;
    try {
      target = decodeConnectPayload(payload);
    } catch (err) {
      send(streamId, EGRESS_ERROR, Buffer.from(err.message));
      return;
    }
    if (streams.has(streamId)) {
      send(streamId, EGRESS_ERROR, Buffer.from('duplicate stream id'));
      return;
    }
    const socket = net.connect({ host: target.host, port: target.port });
    socket.setNoDelay(true);
    const entry = { socket, done: false };
    streams.set(streamId, entry);

    socket.on('connect', () => send(streamId, EGRESS_OK, Buffer.alloc(0)));
    socket.on('data', (chunk) => writeChunks(send, streamId, EGRESS_DATA, chunk));
    socket.on('end', () => finish(streamId, entry, true));
    socket.on('close', () => finish(streamId, entry, true));
    socket.on('error', (err) => {
      if (!entry.done) {
        send(streamId, EGRESS_ERROR, Buffer.from(err.code || 'connect failed'));
        finish(streamId, entry, true);
      }
    });
  };

  conn.on('message', (data) => {
    let frame;
    try {
      frame = decodeEgressFrame(data);
    } catch (err) {
      close(`bad frame: ${err.message}`);
      return;
    }
    const entry = streams.get(frame.streamId);
    if (frame.op === EGRESS_CONNECT) {
      connectTarget(frame.streamId, frame.payload);
      return;
    }
    if (frame.op === EGRESS_DATA) {
      if (entry && !entry.done) entry.socket.write(frame.payload);
      return;
    }
    if (frame.op === EGRESS_CLOSE) {
      if (entry) {
        entry.socket.end();
        finish(frame.streamId, entry, false);
      }
      return;
    }
    close(`unexpected client op ${frame.op}`);
  });

  conn.on('error', (err) => close(err.message));
  conn.on('close', () => close(null));
}

/**
 * Listen for PRAETOR clients and forward their multiplexed TCP streams to
 * arbitrary hosts reachable from this server. DNS resolution happens here, not
 * on the client.
 */
export async function createEgressServer({
  serverKeys,
  host = '0.0.0.0',
  port = 9443,
  cellSize = 1024,
  maxMessageBytes = 64 * 1024 * 1024,
  onLog = () => {},
} = {}) {
  const server = await createPraetorServer({
    serverKeys,
    host,
    port,
    cellSize,
    maxMessageBytes,
    onConnection(conn) {
      onLog(`session ${conn.sessionId.toString('hex').slice(0, 16)} opened`);
      serveConnection(conn, onLog);
    },
    onError(err) {
      onLog(`handshake rejected: ${err.message}`);
    },
  });
  return server;
}
