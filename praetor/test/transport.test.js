import test from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { connectPraetor, createPraetorServer } from '../src/transport.js';
import { concat, generateServerKeypair, randomBytes } from '../src/index.js';

test('TCP transport performs the handshake and carries messages', async () => {
  const serverKeys = generateServerKeypair();
  const server = await createPraetorServer({
    serverKeys,
    port: 0,
    cellSize: 512,
    onConnection: (conn) => {
      conn.on('message', (data) => {
        conn.send(concat(Buffer.from('echo:'), data)).catch(() => {});
      });
    },
  });
  try {
    const client = await connectPraetor({
      port: server.address.port,
      serverPublicKey: serverKeys.publicKey,
      cellSize: 512,
    });
    try {
      const payload = randomBytes(5000);
      const echoed = new Promise((resolve, reject) => {
        client.once('message', resolve);
        client.once('error', reject);
      });
      await client.send(payload);
      assert.deepEqual(await echoed, concat(Buffer.from('echo:'), payload));
      assert.equal(typeof client.sessionId, 'object');
    } finally {
      client.close();
    }
  } finally {
    await server.close();
  }
});

test('a client that does not hold the server key cannot complete', async () => {
  const serverKeys = generateServerKeypair();
  const wrong = generateServerKeypair();
  const server = await createPraetorServer({
    serverKeys,
    port: 0,
    onConnection: () => {},
    onError: () => {},
  });
  try {
    await assert.rejects(
      connectPraetor({
        port: server.address.port,
        serverPublicKey: wrong.publicKey,
        timeoutMs: 5000,
      }),
      /handshake|authentication|failed/i,
    );
  } finally {
    await server.close();
  }
});

test('transport rejects an out-of-range port', async () => {
  await assert.rejects(connectPraetor({ port: 0 }), /port/);
});
