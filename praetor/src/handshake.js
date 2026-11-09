// PRAETOR-HS/1 — one round-trip hybrid handshake.
//
// Properties:
//   * Post-quantum/traditional hybrid: both KEM operations are X-Wing
//     (X25519 + ML-KEM-768), so the session key survives compromise of either
//     algorithm family.
//   * Implicit authentication: the client encapsulates to the server's static
//     hybrid key, so only the real server can derive ss1.
//   * Forward secrecy against later static-key compromise: the server also
//     encapsulates to the client's *ephemeral* hybrid key (ss2). Once the
//     client's ephemeral secret is destroyed, a future compromise of the
//     server's static key cannot recover ss2 or the session key.
//   * Key confirmation in both directions before any payload is accepted.
//   * No cleartext version or algorithm identifier: the negotiated transcript
//     is hashed into the key schedule, so a downgrade changes every key.
//
//   C -> S : ct1 (1120) || ephC.pk (1216) || nonceC (32)          = 2368
//   S -> C : ct2 (1120) || nonceS (32) || confirmS (32)           = 1184
//   C -> S : confirmC (32)
//
//   ss   = SHA3-256("PRAETOR-HS/1" || ss1 || ss2 || ct1 || ct2 || ephC.pk || H(transcript))
//   keys = HKDF-SHA256(ss, salt = H(nonceC || nonceS), info = "PRAETOR/1/session", 96)
//          -> c2s chain (32) || s2c chain (32) || confirm key (32)
import { Buffer } from 'node:buffer';
import {
  ERR,
  PraetorError,
  assert,
  concat,
  ctEqual,
  hkdfSha256,
  hmacSha256,
  randomBytes,
  sha256,
  sha3_256,
  toBytes,
  wipe,
} from './util.js';
import { XWING_CT_BYTES, XWING_PK_BYTES, decapsulate, encapsulate, keygen } from './xwing.js';

const LABEL_SS = Buffer.from('PRAETOR-HS/1');
const LABEL_SESSION = Buffer.from('PRAETOR/1/session');
const LABEL_CONFIRM_S = Buffer.from('PRAETOR/1/server-confirm');
const LABEL_CONFIRM_C = Buffer.from('PRAETOR/1/client-confirm');
const LABEL_SID = Buffer.from('PRAETOR/1/session-id');

export const HS_C1_BYTES = XWING_CT_BYTES + XWING_PK_BYTES + 32;
export const HS_S1_BYTES = XWING_CT_BYTES + 32 + 32;
export const HS_CONFIRM_BYTES = 32;

/** Long-term server key material. */
export function generateServerKeypair() {
  return keygen();
}

function deriveSession({ ss1, ss2, ct1, ct2, ephC, nonceC, nonceS, transcript }) {
  const transcriptHash = sha256(transcript);
  const ss = sha3_256(LABEL_SS, ss1, ss2, ct1, ct2, ephC, transcriptHash);
  const keys = hkdfSha256(ss, sha256(nonceC, nonceS), LABEL_SESSION, 96);
  const sessionId = sha256(LABEL_SID, ss, transcriptHash);
  const out = {
    c2s: Buffer.from(keys.subarray(0, 32)),
    s2c: Buffer.from(keys.subarray(32, 64)),
    confirm: Buffer.from(keys.subarray(64, 96)),
    transcriptHash,
    sessionId,
  };
  wipe(ss);
  wipe(keys);
  wipe(ss1);
  wipe(ss2);
  return out;
}

/**
 * Client step 1. `serverPublicKey` must be pinned or otherwise authenticated
 * out of band; the handshake authenticates possession of its secret half.
 * @param {Uint8Array} serverPublicKey
 */
export function clientInit(serverPublicKey) {
  const serverPk = toBytes(serverPublicKey);
  const eph = keygen();
  const { cipherText: ct1, sharedSecret: ss1 } = encapsulate(serverPk);
  const nonceC = randomBytes(32);
  const message = concat(ct1, eph.publicKey, nonceC);
  assert(message.length === HS_C1_BYTES, ERR.MALFORMED, 'bad client hello size');
  return {
    message,
    state: {
      phase: 'awaiting-server',
      ephSecretKey: eph.secretKey,
      ss1,
      ct1,
      ephPublicKey: eph.publicKey,
      nonceC,
      firstMessage: message,
    },
  };
}

/**
 * Server step. Consumes the client hello and returns the server hello plus a
 * provisional session (no payload may be accepted until `serverFinish`).
 * @param {Uint8Array} serverSecretKey
 * @param {Uint8Array} message
 */
export function serverRespond(serverSecretKey, message) {
  const msg = toBytes(message);
  assert(msg.length === HS_C1_BYTES, ERR.MALFORMED, 'bad client hello size');
  const ct1 = msg.subarray(0, XWING_CT_BYTES);
  const ephC = msg.subarray(XWING_CT_BYTES, XWING_CT_BYTES + XWING_PK_BYTES);
  const nonceC = msg.subarray(XWING_CT_BYTES + XWING_PK_BYTES);

  const ss1 = decapsulate(ct1, serverSecretKey);
  const { cipherText: ct2, sharedSecret: ss2 } = encapsulate(ephC);
  const nonceS = randomBytes(32);
  const transcript = concat(msg, ct2, nonceS);

  const derived = deriveSession({ ss1, ss2, ct1, ct2, ephC, nonceC, nonceS, transcript });
  const confirmS = hmacSha256(derived.confirm, LABEL_CONFIRM_S, derived.transcriptHash);
  const reply = concat(ct2, nonceS, confirmS);
  assert(reply.length === HS_S1_BYTES, ERR.MALFORMED, 'bad server hello size');

  return {
    reply,
    state: {
      phase: 'awaiting-client-confirm',
      derived,
      transcriptHash: derived.transcriptHash,
      sessionId: derived.sessionId,
    },
  };
}

/**
 * Client step 2: verify the server confirmation and produce the client's.
 * @param {ReturnType<typeof clientInit>['state']} state
 * @param {Uint8Array} reply
 */
export function clientFinish(state, reply) {
  assert(state.phase === 'awaiting-server', ERR.POLICY, 'client handshake out of order');
  const msg = toBytes(reply);
  assert(msg.length === HS_S1_BYTES, ERR.MALFORMED, 'bad server hello size');
  const ct2 = msg.subarray(0, XWING_CT_BYTES);
  const nonceS = msg.subarray(XWING_CT_BYTES, XWING_CT_BYTES + 32);
  const confirmS = msg.subarray(XWING_CT_BYTES + 32);
  const transcript = concat(state.firstMessage, ct2, nonceS);

  let ss2;
  try {
    ss2 = decapsulate(ct2, state.ephSecretKey);
  } catch (cause) {
    throw new PraetorError(ERR.AUTH, 'server hello failed to decapsulate', cause);
  }
  const derived = deriveSession({
    ss1: state.ss1,
    ss2,
    ct1: state.ct1,
    ct2,
    ephC: state.ephPublicKey,
    nonceC: state.nonceC,
    nonceS,
    transcript,
  });

  const expected = hmacSha256(derived.confirm, LABEL_CONFIRM_S, derived.transcriptHash);
  if (!ctEqual(expected, confirmS)) {
    throw new PraetorError(ERR.AUTH, 'server key confirmation failed');
  }
  const confirmC = hmacSha256(derived.confirm, LABEL_CONFIRM_C, derived.transcriptHash);
  return {
    confirm: confirmC,
    session: {
      role: 'client',
      sendChain: derived.c2s,
      recvChain: derived.s2c,
      sessionId: derived.sessionId,
    },
  };
}

/**
 * Server step 2: verify the client confirmation, then release the session.
 * @param {ReturnType<typeof serverRespond>['state']} state
 * @param {Uint8Array} confirm
 */
export function serverFinish(state, confirm) {
  assert(state.phase === 'awaiting-client-confirm', ERR.POLICY, 'server handshake out of order');
  const got = toBytes(confirm);
  assert(got.length === HS_CONFIRM_BYTES, ERR.MALFORMED, 'bad client confirmation size');
  const expected = hmacSha256(state.derived.confirm, LABEL_CONFIRM_C, state.transcriptHash);
  if (!ctEqual(expected, got)) {
    throw new PraetorError(ERR.AUTH, 'client key confirmation failed');
  }
  return {
    role: 'server',
    sendChain: state.derived.s2c,
    recvChain: state.derived.c2s,
    sessionId: state.sessionId,
  };
}
