// Padmé length hiding (PETS 2019, "Reducing Metadata Leakage from Encrypted
// Files and Communication with PURBs", §4.4, Algorithm 1).
//
// Padmé groups plaintext lengths into buckets whose length, written as a
// binary float, never has a mantissa longer than its exponent. That caps
// length leakage at O(log log M) bits, compared with O(log M) for fixed
// block padding, for a maximum overhead of ~12% (and far less for large
// payloads).
import { assert, ERR } from './util.js';

/**
 * Padded length for `length` bytes given the maximum message size `maxLength`.
 * @param {number} length
 * @param {number} maxLength
 * @returns {number}
 */
export function padme(length, maxLength) {
  assert(Number.isSafeInteger(length) && length >= 0, ERR.RANGE, 'padmé length must be a safe integer');
  assert(
    Number.isSafeInteger(maxLength) && maxLength >= Math.max(1, length),
    ERR.RANGE,
    'padmé maxLength must be >= length',
  );
  if (length <= 0) return 0;
  if (length === 1) return 1;
  // E = floor(log2(L)), S = floor(log2(E)) + 1, z = E - S
  const E = Math.floor(Math.log2(length));
  const S = Math.floor(Math.log2(E)) + 1;
  const z = E - S;
  if (z <= 0) return length;
  const mask = 2 ** z - 1;
  // Integer round-up clearing the low z bits.
  const padded = Math.floor((length + mask) / 2 ** z) * 2 ** z;
  return padded;
}

/** Number of bits leaked by the padded length, computed for M <= 2^20. */
export function padmeLeakageBits(maxLength) {
  assert(Number.isSafeInteger(maxLength) && maxLength >= 0, ERR.RANGE, 'bad maxLength');
  if (maxLength <= 1) return 0;
  assert(maxLength <= 1 << 20, ERR.RANGE, 'leakage enumeration is limited to 2^20 bytes');
  const seen = new Set();
  for (let L = 1; L <= maxLength; L += 1) seen.add(padme(L, maxLength));
  return Math.ceil(Math.log2(seen.size));
}
