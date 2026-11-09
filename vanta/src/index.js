// VANTA/1 — public API surface.
export {
  ERR,
  VantaError,
  assert,
  concat,
  ctEqual,
  fromBase64,
  fromHex,
  hex,
  randomBytes,
  sha256,
  sha3_256,
  toBase64,
  toBytes,
  wipe,
} from './util.js';

export {
  SealKey,
  open as vsealOpen,
  seal as vsealSeal,
  VSEAL_AEAD_TAG_BYTES,
  VSEAL_DETERMINISTIC_OVERHEAD,
  VSEAL_NONCE_BYTES,
  VSEAL_OVERHEAD,
  VSEAL_PREFIX_BYTES,
  VSEAL_TAG_BYTES,
} from './aead.js';

export {
  AdmissionGate,
  AuditLog,
  CircuitBreaker,
  Keyring,
  TokenBucket,
  hashcash,
  intentAad,
  leadingZeroBits,
  shamirCombine,
  shamirSplit,
  solveChallenge,
  verifySolution,
} from './guard.js';

export { padme, padmeLeakageBits } from './padme.js';

export {
  DEFAULT_RATCHET_INTERVAL,
  RecvRatchet,
  SendRatchet,
  deriveRecordKey,
  stepChain,
} from './ratchet.js';

export {
  XWING_CT_BYTES,
  XWING_LABEL,
  XWING_PK_BYTES,
  XWING_SK_BYTES,
  XWING_SS_BYTES,
  decapsulate as kemDecapsulate,
  encapsulate as kemEncapsulate,
  keygen as kemKeygen,
} from './xwing.js';

export {
  HS_C1_BYTES,
  HS_CONFIRM_BYTES,
  HS_S1_BYTES,
  clientFinish,
  clientInit,
  generateServerKeypair,
  serverFinish,
  serverRespond,
} from './handshake.js';

export {
  Assembler,
  CELL_CTRL,
  CELL_DATA,
  CELL_FIN,
  CELL_HEADER_BYTES,
  CELL_OVERHEAD,
  CELL_PAD,
  CellCipher,
  DEFAULT_CELL_SIZE,
  MAX_CELL_SIZE,
  ReplayWindow,
  SecureChannel,
  coverSchedule,
  packCell,
  unpackCell,
} from './wire.js';

export {
  CONTAINER_VERSION,
  DEFAULT_CHUNK_SIZE,
  decryptBuffer,
  decryptFileSync,
  encryptBuffer,
  encryptFileSync,
  keyFromPassphrase,
} from './container.js';

export const VANTA_VERSION = 'VANTA/1';
export const VSEAL_SUITE = 'VSEAL/1 (HMAC-SHA-256 SIV + ChaCha20-Poly1305 + key commitment)';
