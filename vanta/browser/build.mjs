import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

const root = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const shims = {
  'node:crypto': path.join(root, 'shims', 'crypto.js'),
  'node:fs': path.join(root, 'shims', 'fs.js'),
  // `require.resolve('buffer')` returns Node's builtin name. The trailing
  // slash forces resolution of the installable browser polyfill.
  'node:buffer': require.resolve('buffer/'),
};

const nodeShims = {
  name: 'vanta-node-shims',
  setup(build) {
    build.onResolve({ filter: /^node:/ }, (args) => {
      const shim = shims[args.path];
      if (shim === undefined) {
        throw new Error(`no browser shim registered for ${args.path}`);
      }
      return { path: shim };
    });
  },
};

const common = {
  entryPoints: [path.join(root, 'entry.js')],
  bundle: true,
  platform: 'browser',
  target: ['es2022'],
  plugins: [nodeShims],
  inject: [path.join(root, 'shims', 'buffer-global.js')],
  define: { 'process.env.NODE_ENV': '"production"' },
  logLevel: 'info',
};

mkdirSync(path.join(root, 'dist'), { recursive: true });
await esbuild.build({
  ...common,
  format: 'iife',
  globalName: 'VANTA',
  outfile: path.join(root, 'dist', 'vanta.js'),
});
await esbuild.build({
  ...common,
  format: 'esm',
  outfile: path.join(root, 'dist', 'vanta.mjs'),
});

const template = readFileSync(path.join(root, 'index.html'), 'utf8');
const bundle = readFileSync(path.join(root, 'dist', 'vanta.js'), 'utf8');
writeFileSync(
  path.join(root, 'demo.html'),
  template.replace('<!--VANTA_BUNDLE-->', `<script>\n${bundle}\n</script>`),
);
console.log('browser bundle written: dist/vanta.js, dist/vanta.mjs, demo.html');
