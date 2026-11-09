// VANTA/1 — authenticated streaming transport over TCP.
//
// The handshake is length-framed because its messages are variable size:
//   u32(len) || message
// After the handshake, every unit on the wire is exactly one fixed-size cell
// (cellSize + 80 bytes), so the stream carries no lengths or record markers.
//
// This adapter deliberately does not use TLS: VANTA provides its own hybrid
// post-quantum handshake, encryption and framing. Run it inside a network you
// control or add a TLS layer if you need transport metadata protection too.
import net from 'node:net';
import { EventEmitter } from 'node:events';
import { Buffer } from 'node:buffer';
import {
  CELL_OVERHEAD,
  CELL_PAD,
  DEFAULT_CELL_SIZE,
  SecureChannel,
} from './wire.js';
import { DEFAULT_RATCHET_INTERVAL } from './ratchet.js';
import {
  HS_CONFIRM_BYTES,
  HS_S1_BYTES,
  clientFinish,
  clientInit,
  serverFinish,
  serverRespond,
} from './handshake.js';
import { ERR, VantaError, assert, toBytes } from './util.js';

const MAX_HANDSHAKE_FRAME = 1 << 20;

class ByteReader {
  constructor(socket) {
    this.socket = socket;
    this.queue = Buffer.alloc(0);
    this.error = null;
    this.closed = false;
    this.waiters = [];
    socket.on('data', (chunk) => {
      this.queue = Buffer.concat([this.queue, chunk]);
      this.#pump();
    });
    socket.on('error', (err) => {
      this.error = err;
      this.#pump();
    });
    socket.on('close', () => {
      this.closed = true;
      this.#pump();
    });
  }

  read(size) {
    assert(size > 0 && size <= MAX_HANDSHAKE_FRAME + 16, ERR.RANGE, 'bad read size');
    return new Promise((resolve, reject) => {
      this.waiters.push({ size, resolve, reject });
      this.#pump();
    });
  }

  #pump() {
    while (this.waiters.length > 0) {
      const w = this.waiters[0];
      if (this.queue.length >= w.size) {
        const out = this.queue.subarray(0, w.size);
        this.queue = this.queue.subarray(w.size);
        this.waiters.shift();
        w.resolve(out);
      } else if (this.error !== null) {
        this.waiters.shift();
        w.reject(this.error);
      } else if (this.closed) {
        this.waiters.shift();
        w.reject(new VantaError(ERR.TRUNCATED, 'connection closed mid-frame'));
      } else {
        break;
      }
    }
  }
}

function frame(payload) {
  const body = toBytes(payload);
  const head = Buffer.allocUnsafe(4);
  head.writeUInt32BE(body.length, 0);
  return Buffer.concat([head, body]);
}

async function readFrame(reader) {
  const head = await reader.read(4);
  const len = head.readUInt32BE(0);
  assert(len > 0 && len <= MAX_HANDSHAKE_FRAME, ERR.MALFORMED, 'bad handshake frame length');
  return reader.read(len);
}

function writeAll(socket, data) {
  return new Promise((resolve, reject) => {
    if (socket.destroyed) {
      reject(new VantaError(ERR.TRUNCATED, 'socket is closed'));
      return;
    }
    socket.write(data, (err) => (err ? reject(err) : resolve()));
  });
}

function waitForConnect(socket, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      socket.destroy();
      reject(new VantaError(ERR.TRUNCATED, 'transport connect timed out'));
    }, timeoutMs);
    const onConnect = () => {
      cleanup();
      resolve();
    };
    const onError = (err) => {
      cleanup();
      reject(err);
    };
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('connect', onConnect);
      socket.removeListener('error', onError);
    };
    socket.once('connect', onConnect);
    socket.once('error', onError);
  });
}

/** One authenticated, full-duplex VANTA stream. */
export class VantaConnection extends EventEmitter {
  constructor({
    socket,
    reader,
    session,
    cellSize = DEFAULT_CELL_SIZE,
    ratchetInterval = DEFAULT_RATCHET_INTERVAL,
    maxMessageBytes = 64 * 1024 * 1024,
    autoStart = true,
  }) {
    super();
    this.socket = socket;
    this.reader = reader;
    this.cellSize = cellSize;
    this.wireCellBytes = cellSize + CELL_OVERHEAD;
    this.sessionId = session.sessionId;
    this.channel = new SecureChannel({
      sendChain: session.sendChain,
      recvChain: session.recvChain,
      cellSize,
      ratchetInterval,
      maxMessageBytes,
    });
    this.closed = false;
    this.started = false;
    this.closeEmitted = false;
    socket.once('close', () => this.#finish());
    if (autoStart) this.start();
  }

  start() {
    if (this.started || this.closed) return;
    this.started = true;
    this.pump = this.#pump();
  }

  async #pump() {
    try {
      while (!this.closed) {
        const wire = await this.reader.read(this.wireCellBytes);
        const out = this.channel.receive(wire);
        if (out === null) continue;
        if (out.type === CELL_PAD) {
          this.emit('padding');
          continue;
        }
        // `receive` returns progress objects for intermediate fragments. Only
        // a completed message may surface on `message`; fragments are exposed
        // separately for callers that want progress accounting.
        if (out.data !== undefined) this.emit('message', out.data, out);
        else this.emit('fragment', out);
      }
    } catch (err) {
      if (!this.closed && this.listenerCount('error') > 0) this.emit('error', err);
    } finally {
      this.#finish();
    }
  }

  async send(data) {
    if (this.closed) throw new VantaError(ERR.TRUNCATED, 'connection is closed');
    const cells = this.channel.send(toBytes(data, 'message'));
    for (const cell of cells) {
      // Await the write callback so a slow peer applies backpressure instead
      // of letting an unbounded queue grow in memory.
      await writeAll(this.socket, cell);
    }
    return cells.length;
  }

  async sendPadding() {
    if (this.closed) throw new VantaError(ERR.TRUNCATED, 'connection is closed');
    await writeAll(this.socket, this.channel.sendPadding());
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.socket.end();
    this.channel.destroy();
  }

  destroy(err) {
    this.closed = true;
    if (err !== undefined && this.listenerCount('error') > 0) this.emit('error', err);
    this.socket.destroy();
  }

  #finish() {
    if (this.closeEmitted) return;
    this.closeEmitted = true;
    this.closed = true;
    this.channel.destroy();
    this.emit('close');
  }
}

/**
 * Connect to a VANTA TCP server. The server public key must be pinned.
 * @returns {Promise<VantaConnection>}
 */
export async function connectVanta({
  host = '127.0.0.1',
  port,
  serverPublicKey,
  cellSize = DEFAULT_CELL_SIZE,
  ratchetInterval = DEFAULT_RATCHET_INTERVAL,
  maxMessageBytes = 64 * 1024 * 1024,
  timeoutMs = 15_000,
} = {}) {
  assert(Number.isInteger(port) && port > 0 && port <= 65535, ERR.RANGE, 'valid port required');
  assert(serverPublicKey !== undefined, ERR.KEY, 'server public key is required');
  const socket = net.connect({ host, port });
  socket.setNoDelay(true);
  const reader = new ByteReader(socket);
  try {
    await waitForConnect(socket, timeoutMs);
    const { message, state } = clientInit(serverPublicKey);
    await writeAll(socket, frame(message));
    const reply = await readFrame(reader);
    assert(reply.length === HS_S1_BYTES, ERR.MALFORMED, 'bad server hello size');
    const { confirm, session } = clientFinish(state, reply);
    assert(confirm.length === HS_CONFIRM_BYTES, ERR.MALFORMED, 'bad client confirmation size');
    await writeAll(socket, frame(confirm));
    const conn = new VantaConnection({
      socket,
      reader,
      session,
      cellSize,
      ratchetInterval,
      maxMessageBytes,
      autoStart: false,
    });
    // Give the caller one event-loop turn to attach listeners before cells
    // can be emitted.
    setImmediate(() => conn.start());
    return conn;
  } catch (err) {
    socket.destroy();
    if (err instanceof VantaError) throw err;
    throw new VantaError(ERR.AUTH, 'VANTA transport handshake failed', err);
  }
}

/**
 * Listen for VANTA clients. `onConnection` receives an authenticated stream
 * before the receive pump starts, so listeners attached inside it cannot miss
 * the first cell.
 */
export async function createVantaServer({
  serverKeys,
  onConnection,
  host = '127.0.0.1',
  port = 0,
  cellSize = DEFAULT_CELL_SIZE,
  ratchetInterval = DEFAULT_RATCHET_INTERVAL,
  maxMessageBytes = 64 * 1024 * 1024,
  timeoutMs = 15_000,
  onError = () => {},
} = {}) {
  assert(serverKeys?.secretKey !== undefined, ERR.KEY, 'server keypair required');
  assert(typeof onConnection === 'function', ERR.POLICY, 'onConnection callback required');

  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.setNoDelay(true);
    const reader = new ByteReader(socket);
    (async () => {
      socket.setTimeout(timeoutMs, () => {
        socket.destroy(new VantaError(ERR.TRUNCATED, 'handshake timed out'));
      });
      const hello = await readFrame(reader);
      const { reply, state } = serverRespond(serverKeys.secretKey, hello);
      await writeAll(socket, frame(reply));
      const confirm = await readFrame(reader);
      const session = serverFinish(state, confirm);
      socket.setTimeout(0);
      const conn = new VantaConnection({
        socket,
        reader,
        session,
        cellSize,
        ratchetInterval,
        maxMessageBytes,
        autoStart: false,
      });
      await onConnection(conn);
      conn.start();
    })().catch((err) => {
      onError(err);
      socket.destroy();
    });
  });

  await new Promise((resolve, reject) => {
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

  return {
    server,
    address: server.address(),
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(() => resolve()));
    },
  };
}
