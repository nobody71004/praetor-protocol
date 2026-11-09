import assert from 'node:assert/strict';
import * as VANTA from './dist/vanta.mjs';

const server = VANTA.generateServerKeypair();
const client = VANTA.clientInit(server.publicKey);
const serverSide = VANTA.serverRespond(server.secretKey, client.message);
const clientSide = VANTA.clientFinish(client.state, serverSide.reply);
const serverSession = VANTA.serverFinish(serverSide.state, clientSide.confirm);

assert.deepEqual(clientSide.session.sendChain, serverSession.recvChain);
assert.deepEqual(clientSide.session.sessionId, serverSession.sessionId);

const a = new VANTA.SecureChannel({ ...clientSide.session, cellSize: 512 });
const b = new VANTA.SecureChannel({ ...serverSession, cellSize: 512 });
const message = VANTA.randomBytes(5000);
let received = null;
for (const cell of a.send(message)) {
  const out = b.receive(cell);
  if (out?.data) received = out.data;
}
assert.equal(VANTA.hex(received), VANTA.hex(message));

const key = VANTA.randomBytes(32);
const envelope = VANTA.vsealSeal(key, Buffer.from('browser parity'), Buffer.from('aad'));
assert.equal(
  VANTA.hex(VANTA.vsealOpen(key, envelope, Buffer.from('aad'))),
  VANTA.hex(Buffer.from('browser parity')),
);

const kem = VANTA.kemKeygen();
const enc = VANTA.kemEncapsulate(kem.publicKey);
assert.equal(
  VANTA.hex(VANTA.kemDecapsulate(enc.cipherText, kem.secretKey)),
  VANTA.hex(enc.sharedSecret),
);

const container = VANTA.encryptBuffer(Buffer.from('container in browser'), key);
const opened = VANTA.decryptBuffer(container, key);
assert.equal(VANTA.hex(opened.plaintext), VANTA.hex(Buffer.from('container in browser')));

console.log('browser bundle: PASS (handshake, cells, VSEAL, KEM, container)');
