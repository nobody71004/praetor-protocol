import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ERR,
  HS_C1_BYTES,
  HS_S1_BYTES,
  SecureChannel,
  PraetorError,
  clientFinish,
  clientInit,
  generateServerKeypair,
  kemDecapsulate as decapsulate,
  kemEncapsulate as encapsulate,
  kemKeygen,
  randomBytes,
  serverFinish,
  serverRespond,
} from '../src/index.js';

function fullHandshake() {
  const server = generateServerKeypair();
  const client = clientInit(server.publicKey);
  assert.equal(client.message.length, HS_C1_BYTES);
  const serverSide = serverRespond(server.secretKey, client.message);
  assert.equal(serverSide.reply.length, HS_S1_BYTES);
  const clientSide = clientFinish(client.state, serverSide.reply);
  const session = serverFinish(serverSide.state, clientSide.confirm);
  return { clientSide, session, server };
}

test('both sides derive mirrored keys and the same session id', () => {
  const { clientSide, session } = fullHandshake();
  assert.deepEqual(clientSide.session.sendChain, session.recvChain);
  assert.deepEqual(clientSide.session.recvChain, session.sendChain);
  assert.deepEqual(clientSide.session.sessionId, session.sessionId);
  assert.notDeepEqual(clientSide.session.sendChain, clientSide.session.recvChain);
});

test('a full channel works after the handshake', () => {
  const { clientSide, session } = fullHandshake();
  const c = new SecureChannel({ ...clientSide.session, cellSize: 512 });
  const s = new SecureChannel({ ...session, cellSize: 512 });
  const msg = randomBytes(2048);
  const out = s.receive(c.send(msg)[0]);
  assert.ok(out);
});

test('tampering with any handshake byte is detected', () => {
  const server = generateServerKeypair();
  const client = clientInit(server.publicKey);
  const serverSide = serverRespond(server.secretKey, client.message);
  for (const idx of [0, 32, 1100, 1200, 2360]) {
    const bad = Buffer.from(serverSide.reply);
    bad[idx] ^= 0x01;
    assert.throws(
      () => clientFinish(client.state, bad),
      (e) => e instanceof PraetorError && e.code === ERR.AUTH,
      `flip at ${idx} not detected`,
    );
  }
});

test('an impostor server holding the public key cannot complete', () => {
  const real = generateServerKeypair();
  const impostor = generateServerKeypair();
  const client = clientInit(real.publicKey);
  // Impostor answers with its own encapsulation; transcript keys differ.
  const fake = serverRespond(impostor.secretKey, client.message);
  assert.throws(() => clientFinish(client.state, fake.reply), /failed|decapsulate/i);
});

test('client confirmation is required before the server releases a session', () => {
  const server = generateServerKeypair();
  const client = clientInit(server.publicKey);
  const serverSide = serverRespond(server.secretKey, client.message);
  assert.throws(() => serverFinish(serverSide.state, Buffer.alloc(32)), /confirmation/);
  assert.throws(() => serverFinish(serverSide.state, Buffer.alloc(31)), /size/);
});

test('hybrid KEM encapsulate/decapsulate roundtrips', () => {
  const kp = kemKeygen();
  const { cipherText, sharedSecret } = encapsulate(kp.publicKey);
  assert.equal(cipherText.length, 1120);
  assert.deepEqual(decapsulate(cipherText, kp.secretKey), sharedSecret);
});

test('KEM implicit rejection yields a wrong, not leaked, secret', () => {
  const kp = kemKeygen();
  const real = encapsulate(kp.publicKey).sharedSecret;
  // ML-KEM decapsulation never throws on a malformed ciphertext; it returns a
  // pseudorandom secret (FIPS 203 implicit rejection), so callers must rely on
  // the handshake confirmation rather than on a decapsulation error.
  const bogus = decapsulate(randomBytes(1120), kp.secretKey);
  assert.equal(bogus.length, 32);
  assert.notDeepEqual(bogus, real);
  assert.throws(() => decapsulate(randomBytes(10), kp.secretKey), /length/);
});

test('session id is bound to the transcript', () => {
  const a = fullHandshake();
  const b = fullHandshake();
  assert.equal(a.clientSide.session.sessionId.length, 32);
  assert.notDeepEqual(a.clientSide.session.sessionId, b.clientSide.session.sessionId);
});
