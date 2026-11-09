// The browser build exposes the in-memory APIs only. Importing the container
// module must not crash, so every filesystem entry point is a clear stub.
const message = 'file APIs are not available in the browser build; use encryptBuffer/decryptBuffer';

function unavailable() {
  throw new Error(message);
}

export const openSync = unavailable;
export const closeSync = unavailable;
export const readSync = unavailable;
export const writeSync = unavailable;
export const fstatSync = unavailable;
export const fsyncSync = unavailable;
export const renameSync = unavailable;
export const unlinkSync = unavailable;
