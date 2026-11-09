# Browser client

The browser build runs the **same core modules** as Node — it is not a separate
protocol implementation.

```bash
cd praetor
npm install
npm run build:browser   # dist/praetor.js (IIFE), dist/praetor.mjs (ESM), demo.html
npm run test:browser    # parity test in Node against the shims
```

Open `browser/demo.html` directly (it has the bundle inlined) and press **Run
protocol self-test**. It performs a full handshake, a 5 KB message through a
512-byte fixed-cell channel, a PSEAL seal/open and a container roundtrip, all
in page memory.

## How the shims work

`browser/build.mjs` bundles `browser/entry.js` with esbuild and redirects the
Node modules used by the core:

| Node import | Browser replacement |
|---|---|
| `node:crypto` | `browser/shims/crypto.js` — WebCrypto randomness; Noble SHA-2/SHA-3, HMAC, HKDF, scrypt, ChaCha20-Poly1305 |
| `node:buffer` | the `buffer` npm polyfill |
| `node:fs` | throwing stubs; only `encryptBuffer`/`decryptBuffer` are available |

The output is a 268 KB IIFE (`PRAETOR` global) and a 251 KB ESM module. No Node
built-ins or native addons are required at runtime.

## Verified

* Chromium (the packaged local browser) executed the demo successfully:
  `{handshake: true, channel: true, aead: true, container: true, cells: 11}`.
* `npm run test:browser` checks the ESM bundle for the same handshake, cell
  reassembly, PSEAL, KEM and container behavior.

## Limits

* The bundle is not constant-time, and pure-JS scrypt (used only for
  passphrase containers) is slow. Prefer raw-key containers in the browser.
* Keys live in page memory; there is no WebCrypto non-extractable key custody
  for ChaCha20-Poly1305 or ML-KEM.
* `node:fs` is intentionally unavailable. Do not import the CLI in a browser.
* A browser tab is not a secure enclave: XSS or a malicious extension can read
  page memory. Serve the page with a strict CSP and no third-party scripts.
