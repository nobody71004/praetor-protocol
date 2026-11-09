// PRAETOR/1 — local SOCKS5/SOCKS4 bridge over one PRAETOR egress session.
//
// The app (or a CLI) listens on loopback and browsers point at it as a SOCKS
// proxy. Each CONNECT becomes one multiplexed stream inside the single PRAETOR
// session established here. Target names are passed to the server unresolved,
// so the exit performs DNS and the client cannot leak its local resolver.
import net from 'node:net';
import { Buffer } from 'node:buffer';
import { connectPraetor } from './transport.js';
import {
  EGRESS_CLOSE,
  EGRESS_CONNECT,
  EGRESS_DATA,
  EGRESS_ERROR,
  EGRESS_OK,
  MAX_EGRESS_PAYLOAD,
  decodeEgressFrame,
  encodeConnectPayload,
  encodeEgressFrame,
} from './egress.js';

const SOCKS_VERSION = 5;
const SOCKS4_VERSION = 4;
const SOCKS4_GRANTED = 90;
const SOCKS4_REJECTED = 91;
const SOCKS_SUCCEEDED = 0;
const SOCKS_FAILURE = 1;
const SOCKS_CONNECTION_REFUSED = 5;
const SOCKS_COMMAND_UNSUPPORTED = 7;
const SOCKS_ATYP_UNSUPPORTED = 8;
const MAX_PENDING_BYTES = 1 << 20;

function socksReply(socket, code, version = SOCKS_VERSION) {
  if (socket.destroyed) return;
  if (version === SOCKS4_VERSION) {
    const status = code === SOCKS_SUCCEEDED ? SOCKS4_GRANTED : SOCKS4_REJECTED;
    socket.write(Buffer.from([0, status, 0, 0, 0, 0, 0, 0]));
    return;
  }
  socket.write(Buffer.from([SOCKS_VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0]));
}

function readIpv6(buf) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(buf.readUInt16BE(i).toString(16));
  return groups.join(':');
}

function listen(server, host, port) {
  return new Promise((resolve, reject) => {
    const onError = (err) => {
      server.removeListener('listening', onListening);
      reject(err);
    };
    const onListening = () => {
      server.removeListener('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, host);
  });
}

/**
 * Open one PRAETOR session and expose a SOCKS5 proxy on loopback.
 *
 * @returns {Promise<{port:number, handshakeMs:number, sessionId:Buffer,
 *   stats:() => {tx:number, rx:number}, close:() => void}>}
 */
export async function startSocksProxy({
  serverPublicKey,
  host,
  port,
  cellSize = 1024,
  proxyHost = '127.0.0.1',
  proxyPort = 0,
  connectTimeoutMs = 15000,
  maxMessageBytes = 64 * 1024 * 1024,
  onTraffic = () => {},
  onError = () => {},
  onLog = () => {},
} = {}) {
  const started = Date.now();
  const conn = await connectPraetor({
    host,
    port,
    serverPublicKey,
    cellSize,
    maxMessageBytes,
    timeoutMs: connectTimeoutMs,
  });
  const handshakeMs = Date.now() - started;

  let stopped = false;
  let nextStreamId = 1;
  let tx = 0;
  let rx = 0;
  const streams = new Map();
  const socksSockets = new Set();
  let server = null;

  const cleanup = (stream) => {
    streams.delete(stream.id);
    socksSockets.delete(stream.socket);
  };

  const stopAll = (err) => {
    if (stopped) return;
    stopped = true;
    for (const stream of streams.values()) stream.socket.destroy();
    streams.clear();
    for (const socket of socksSockets) socket.destroy();
    socksSockets.clear();
    if (server) {
      try {
        server.close();
      } catch {
        /* not listening */
      }
    }
    try {
      conn.close();
    } catch {
      /* already closed */
    }
    if (err) {
      onLog(`session ended: ${err.message}`);
      onError(err);
    }
  };

  const send = (streamId, op, payload) => {
    if (stopped) return;
    conn.send(encodeEgressFrame(streamId, op, payload)).catch(stopAll);
  };

  const sendStreamData = (stream, chunk) => {
    for (let offset = 0; offset < chunk.length; offset += MAX_EGRESS_PAYLOAD) {
      const part = chunk.subarray(offset, offset + MAX_EGRESS_PAYLOAD);
      tx += part.length;
      onTraffic('tx', part.length);
      send(stream.id, EGRESS_DATA, part);
    }
  };

  conn.on('message', (data) => {
    let frame;
    try {
      frame = decodeEgressFrame(data);
    } catch (err) {
      stopAll(err);
      return;
    }
    const stream = streams.get(frame.streamId);
    if (!stream) return;

    if (frame.op === EGRESS_OK) {
      if (stream.connected) return;
      stream.connected = true;
      socksReply(stream.socket, SOCKS_SUCCEEDED, stream.socksVersion);
      const pending = stream.pending;
      stream.pending = [];
      for (const chunk of pending) sendStreamData(stream, chunk);
      return;
    }

    if (frame.op === EGRESS_DATA) {
      rx += frame.payload.length;
      onTraffic('rx', frame.payload.length);
      if (stream.connected) stream.socket.write(frame.payload);
      else if (stream.pendingBytes < MAX_PENDING_BYTES) {
        stream.pending.push(Buffer.from(frame.payload));
        stream.pendingBytes += frame.payload.length;
      }
      return;
    }

    if (frame.op === EGRESS_ERROR) {
      const reason = frame.payload.toString('utf8') || 'target unreachable';
      if (!stream.connected) {
        socksReply(stream.socket, SOCKS_CONNECTION_REFUSED, stream.socksVersion);
        stream.socket.destroy();
      } else {
        stream.socket.destroy();
      }
      cleanup(stream);
      onLog(`stream ${frame.streamId} failed: ${reason}`);
      return;
    }

    if (frame.op === EGRESS_CLOSE) {
      if (!stream.connected) socksReply(stream.socket, SOCKS_FAILURE, stream.socksVersion);
      stream.socket.end();
      cleanup(stream);
    }
  });

  conn.on('error', (err) => stopAll(err));
  conn.on('close', () => {
    if (!stopped) stopAll(new Error('PRAETOR session closed'));
  });

  server = net.createServer((socket) => {
    socket.setNoDelay(true);
    socksSockets.add(socket);
    let buffer = Buffer.alloc(0);
    let stage = 0;
    let stream = null;

    const handleSocksData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      parse();
    };

    const openStream = (targetHost, targetPort, socksVersion) => {
      const id = nextStreamId;
      nextStreamId = (nextStreamId + 1) >>> 0;
      if (nextStreamId === 0) nextStreamId = 1;
      stream = {
        id,
        socket,
        socksVersion,
        connected: false,
        pending: [],
        pendingBytes: 0,
        done: false,
      };
      streams.set(id, stream);
      send(id, EGRESS_CONNECT, encodeConnectPayload(targetHost, targetPort));
    };

    const parse = () => {
      for (;;) {
        if (stage === 0) {
          if (buffer.length < 1) return;
          if (buffer[0] === SOCKS4_VERSION) {
            stage = 4;
            continue;
          }
          if (buffer[0] !== SOCKS_VERSION) {
            socket.destroy();
            return;
          }
          if (buffer.length < 2) return;
          const methodCount = buffer[1];
          if (buffer.length < 2 + methodCount) return;
          const methods = buffer.subarray(2, 2 + methodCount);
          if (!methods.includes(0)) {
            socket.end(Buffer.from([SOCKS_VERSION, 0xff]));
            return;
          }
          socket.write(Buffer.from([SOCKS_VERSION, 0]));
          buffer = buffer.subarray(2 + methodCount);
          stage = 1;
          continue;
        }

        if (stage === 4) {
          // SOCKS4 CONNECT, including SOCKS4a hostnames. Windows advertises a
          // `socks=` system proxy as SOCKS4, so Chromium lands here.
          if (buffer.length < 9) return;
          if (buffer[1] !== 1) {
            socksReply(socket, SOCKS_FAILURE, SOCKS4_VERSION);
            socket.destroy();
            return;
          }
          const targetPort = buffer.readUInt16BE(2);
          const ip = buffer.subarray(4, 8);
          let offset = 8;
          while (offset < buffer.length && buffer[offset] !== 0) offset += 1;
          if (offset >= buffer.length) return;
          offset += 1;
          let targetHost;
          if (ip[0] === 0 && ip[1] === 0 && ip[2] === 0 && ip[3] !== 0) {
            const end = buffer.indexOf(0, offset);
            if (end === -1) return;
            targetHost = buffer.subarray(offset, end).toString('utf8');
            offset = end + 1;
          } else {
            targetHost = `${ip[0]}.${ip[1]}.${ip[2]}.${ip[3]}`;
          }
          if (!targetHost || targetPort === 0) {
            socksReply(socket, SOCKS_FAILURE, SOCKS4_VERSION);
            socket.destroy();
            return;
          }
          buffer = buffer.subarray(offset);
          stage = 2;
          openStream(targetHost, targetPort, SOCKS4_VERSION);
          continue;
        }

        if (stage === 1) {
          if (buffer.length < 4) return;
          if (buffer[0] !== SOCKS_VERSION) {
            socket.destroy();
            return;
          }
          if (buffer[1] !== 1) {
            socksReply(socket, SOCKS_COMMAND_UNSUPPORTED);
            socket.destroy();
            return;
          }
          const addressType = buffer[3];
          let targetHost;
          let targetPort;
          let need;
          if (addressType === 1) {
            need = 4 + 4 + 2;
            if (buffer.length < need) return;
            targetHost = `${buffer[4]}.${buffer[5]}.${buffer[6]}.${buffer[7]}`;
            targetPort = buffer.readUInt16BE(8);
          } else if (addressType === 3) {
            if (buffer.length < 5) return;
            const nameLen = buffer[4];
            need = 5 + nameLen + 2;
            if (buffer.length < need) return;
            targetHost = buffer.subarray(5, 5 + nameLen).toString('utf8');
            targetPort = buffer.readUInt16BE(5 + nameLen);
          } else if (addressType === 4) {
            need = 4 + 16 + 2;
            if (buffer.length < need) return;
            targetHost = readIpv6(buffer.subarray(4, 20));
            targetPort = buffer.readUInt16BE(20);
          } else {
            socksReply(socket, SOCKS_ATYP_UNSUPPORTED);
            socket.destroy();
            return;
          }
          buffer = buffer.subarray(need);
          stage = 2;
          openStream(targetHost, targetPort, SOCKS_VERSION);
          continue;
        }

        if (!stream || stream.done) return;
        const chunk = buffer;
        buffer = Buffer.alloc(0);
        if (!chunk.length) return;
        if (stream.connected) {
          sendStreamData(stream, chunk);
        } else if (stream.pendingBytes < MAX_PENDING_BYTES) {
          stream.pending.push(Buffer.from(chunk));
          stream.pendingBytes += chunk.length;
        }
        return;
      }
    };

    socket.on('data', handleSocksData);
    socket.on('error', () => {});
    socket.on('close', () => {
      socksSockets.delete(socket);
      if (stream && !stream.done && streams.has(stream.id)) {
        stream.done = true;
        send(stream.id, EGRESS_CLOSE, Buffer.alloc(0));
        cleanup(stream);
      }
    });
  });

  try {
    await listen(server, proxyHost, proxyPort);
  } catch (error) {
    try {
      conn.close();
    } catch {
      /* already closed */
    }
    throw error;
  }
  server.on('error', (error) => stopAll(error));
  const boundPort = server.address().port;
  onLog(`SOCKS proxy listening on ${proxyHost}:${boundPort}`);

  return {
    port: boundPort,
    handshakeMs,
    sessionId: conn.sessionId,
    stats: () => ({ tx, rx }),
    close() {
      if (stopped) return;
      stopped = true;
      for (const stream of streams.values()) stream.socket.destroy();
      streams.clear();
      for (const socket of socksSockets) socket.destroy();
      socksSockets.clear();
      server.close();
      try {
        conn.close();
      } catch {
        /* already closed */
      }
    },
  };
}
