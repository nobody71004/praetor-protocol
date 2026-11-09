import assert from 'node:assert/strict';
import * as PRAETOR from './dist/praetor.mjs';

const server = PRAETOR.generateServerKeypair();
const client = PRAETOR.clientInit(server.publicKey);
const serverSide = PRAETOR.serverRespond(server.secretKey, client.message);
const clientSide = PRAETOR.clientFinish(client.state, serverSide.reply);
const serverSession = PRAETOR.serverFinish(serverSide.state, clientSide.confirm);

assert.deepEqual(clientSide.session.sendChain, serverSession.recvChain);
assert.deepEqual(clientSide.session.sessionId, serverSession.sessionId);

const a = new PRAETOR.SecureChannel({ ...clientSide.session, cellSize: 512 });
const b = new PRAETOR.SecureChannel({ ...serverSession, cellSize: 512 });
const message = PRAETOR.randomBytes(5000);
let received = null;
for (const cell of a.send(message)) {
  const out = b.receive(cell);
  if (out?.data) received = out.data;
}
assert.equal(PRAETOR.hex(received), PRAETOR.hex(message));

const key = PRAETOR.randomBytes(32);
const envelope = PRAETOR.psealSeal(key, Buffer.from('browser parity'), Buffer.from('aad'));
assert.equal(
  PRAETOR.hex(PRAETOR.psealOpen(key, envelope, Buffer.from('aad'))),
  PRAETOR.hex(Buffer.from('browser parity')),
);

const kem = PRAETOR.kemKeygen();
const enc = PRAETOR.kemEncapsulate(kem.publicKey);
assert.equal(
  PRAETOR.hex(PRAETOR.kemDecapsulate(enc.cipherText, kem.secretKey)),
  PRAETOR.hex(enc.sharedSecret),
);

const container = PRAETOR.encryptBuffer(Buffer.from('container in browser'), key);
const opened = PRAETOR.decryptBuffer(container, key);
assert.equal(PRAETOR.hex(opened.plaintext), PRAETOR.hex(Buffer.from('container in browser')));

console.log('browser bundle: PASS (handshake, cells, PSEAL, KEM, container)');
