// Render the PRAETOR vs WireGuard chart from measured JSON only.
// Usage: node bench/chart-vs-wireguard.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const praetor = JSON.parse(readFileSync(path.join(here, 'results-praetor.json'), 'utf8'));
const wg = JSON.parse(readFileSync(path.join(here, 'results-wireguard.json'), 'utf8'));

// The zero-copy buffer paths are the fair comparison to boringtun, which also
// writes into a caller buffer and hands back a slice.
const fastRows = praetor.fast_buffer ?? praetor.fast_cells;
const praetor1k = praetor.cells.find((r) => r.size === 1008);
const praetor60 = praetor.cells.find((r) => r.size === 60000);
const fast1k = fastRows.find((r) => r.size === 1008);
const fast60 = fastRows.find((r) => r.size === 60000);
const bolt1k = praetor.bolt_cells.find((r) => r.size === 1008 && r.mode === 'zero_copy');
const bolt60 = praetor.bolt_cells.find((r) => r.size === 60000 && r.mode === 'zero_copy');
const wg1k = wg.transport.find((r) => r.size === 1024);
const wg60 = wg.transport.find((r) => r.size === 60000);

if (!praetor1k || !praetor60 || !fast1k || !fast60 || !bolt1k || !bolt60 || !wg1k || !wg60) {
  throw new Error('benchmark rows missing');
}

const fmtInt = (n) => Math.round(n).toLocaleString('en-US');
const fmtOne = (n) => n.toFixed(1);
const ratio = (v, w) => (v / w).toFixed(2);

const W = 1040;
const H = 980;
const LEFT = 250;
const TRACK = 660;
const MINT = '#5ce1b0';
const AMBER = '#ffc46b';
const VIOLET = '#c9a2ff';
const BLUE = '#6aa9ff';
const INK = '#e7f2ea';
const MUTED = '#8fa6a1';
const GRID = '#22323a';

function panel(y, title, note, rows, format, unit) {
  const max = Math.max(...rows.map(([, value]) => value)) * 1.08;
  const top = y + 42;
  const bars = rows
    .map(([label, value, color, annotation], i) => {
      const width = (value / max) * TRACK;
      const row = top + i * 50;
      const note = annotation
        ? `<text x="${LEFT - 16}" y="${row + 22}" text-anchor="end" fill="${MUTED}" font-size="13" font-weight="600">${annotation}</text>`
        : '';
      return `
    <rect x="${LEFT}" y="${row}" width="${TRACK}" height="34" rx="7" fill="#152027" stroke="${GRID}"/>
    <rect x="${LEFT}" y="${row}" width="${Math.max(2, width)}" height="34" rx="7" fill="${color}"/>
    <text x="56" y="${row + 22}" fill="${INK}" font-size="15" font-weight="600">${label}</text>
    ${note}
    <text x="${LEFT + Math.max(width, 2) + 10}" y="${row + 22}" fill="${color}" font-size="15" font-weight="700">${format(value)}</text>`;
    })
    .join('');
  return `
  <g>
    <text x="56" y="${y}" fill="${INK}" font-size="19" font-weight="700">${title}</text>
    <text x="56" y="${y + 22}" fill="${MUTED}" font-size="13">${note} · ${unit}</text>
    ${bars}
  </g>`;
}

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-labelledby="title desc" font-family="Segoe UI, Arial, sans-serif">
  <title id="title">PRAETOR/1 profiles versus WireGuard on the same CPU</title>
  <desc id="desc">Grouped bar chart of handshakes per second, 1 KiB authenticated roundtrips per second, and 60 KB full-path throughput. PSEAL is the strong default, FAST is AES-256-GCM, BOLT is AEGIS-128L. All transport rows use the same zero-copy buffer API. WireGuard is boringtun userspace.</desc>
  <rect width="${W}" height="${H}" fill="#0b0f12"/>
  <text x="56" y="62" fill="${INK}" font-size="30" font-weight="800" letter-spacing="-0.5">PRAETOR/1 profiles vs WireGuard</text>
  <text x="56" y="92" fill="${MUTED}" font-size="14">Same machine · single thread · Rust release builds · higher is better</text>
  <g font-family="Segoe UI, Arial, sans-serif">
    <rect x="${W - 392}" y="46" width="14" height="14" rx="3" fill="${MINT}"/>
    <text x="${W - 370}" y="58" fill="${INK}" font-size="13">PSEAL</text>
    <rect x="${W - 308}" y="46" width="14" height="14" rx="3" fill="${AMBER}"/>
    <text x="${W - 286}" y="58" fill="${INK}" font-size="13">FAST</text>
    <rect x="${W - 226}" y="46" width="14" height="14" rx="3" fill="${VIOLET}"/>
    <text x="${W - 204}" y="58" fill="${INK}" font-size="13">BOLT</text>
    <rect x="${W - 140}" y="46" width="14" height="14" rx="3" fill="${BLUE}"/>
    <text x="${W - 118}" y="58" fill="${INK}" font-size="13">WireGuard</text>
  </g>
  <line x1="56" y1="116" x2="${W - 56}" y2="116" stroke="${GRID}"/>
  ${panel(156, 'Handshakes per second', 'PSEAL, FAST and BOLT share this handshake; ratios are versus WireGuard', [
    ['PRAETOR PSEAL', praetor.handshake_ops_s, MINT, `${ratio(praetor.handshake_ops_s, wg.handshake_ops_s)}×`],
    ['PRAETOR FAST', praetor.handshake_ops_s, AMBER, `${ratio(praetor.handshake_ops_s, wg.handshake_ops_s)}×`],
    ['PRAETOR BOLT', praetor.handshake_ops_s, VIOLET, `${ratio(praetor.handshake_ops_s, wg.handshake_ops_s)}×`],
    ['WireGuard', wg.handshake_ops_s, BLUE, '1.00×'],
  ], fmtInt, 'ops/s')}
  ${panel(406, '1 KiB authenticated roundtrips', 'one fixed cell or one WireGuard transport packet', [
    ['PRAETOR PSEAL', praetor1k.ops_s, MINT],
    ['PRAETOR FAST', fast1k.ops_s, AMBER],
    ['PRAETOR BOLT', bolt1k.ops_s, VIOLET],
    ['WireGuard', wg1k.ops_s, BLUE],
  ], fmtInt, 'roundtrips/s')}
  ${panel(656, '60 KB full-path throughput', 'fixed-cell framing vs WireGuard transport packet', [
    ['PRAETOR PSEAL', praetor60.mib_s, MINT],
    ['PRAETOR FAST', fast60.mib_s, AMBER],
    ['PRAETOR BOLT', bolt60.mib_s, VIOLET],
    ['WireGuard', wg60.mib_s, BLUE],
  ], fmtOne, 'MiB/s')}
  <text x="56" y="906" fill="${MUTED}" font-size="12">BOLT: ${ratio(bolt1k.ops_s, wg1k.ops_s)}× WireGuard's 1 KiB roundtrip rate and ${ratio(bolt60.mib_s, wg60.mib_s)}× its 60 KB throughput on this CPU.</text>
  <text x="56" y="924" fill="${MUTED}" font-size="12">BOLT is AEGIS-128L (ISO/IEC 29192-8) with a 64-bit cell counter and key commitment, but no SIV and only a 128-bit key, so PSEAL remains the default.</text>
  <text x="56" y="942" fill="${MUTED}" font-size="12">FAST is AES-256-GCM via ring: ${ratio(fast1k.ops_s, wg1k.ops_s)}× the 1 KiB rate and ${ratio(fast60.mib_s, wg60.mib_s)}× the 60 KB throughput. PSEAL pays for two-pass SIV, a 32-byte tag and 80-byte cells.</text>
  <text x="56" y="960" fill="${MUTED}" font-size="12">Handshakes are ${ratio(praetor.handshake_ops_s, wg.handshake_ops_s)}× WireGuard's: X25519 DH dominates; libcrux ML-KEM is no longer the bottleneck. WireGuard is boringtun 0.7.1; no TUN/UDP, so these are protocol CPU costs.</text>
</svg>
`;

const out = path.join(here, '..', 'docs', 'benchmarks-praetor-vs-wireguard.svg');
writeFileSync(out, svg);
console.log(`wrote ${out}`);
console.log(JSON.stringify({
  handshakes: [praetor.handshake_ops_s, wg.handshake_ops_s],
  roundtrip_1k: [praetor1k.ops_s, fast1k.ops_s, bolt1k.ops_s, wg1k.ops_s],
  throughput_60k: [praetor60.mib_s, fast60.mib_s, bolt60.mib_s, wg60.mib_s],
  ratios: {
    pseal: [ratio(praetor1k.ops_s, wg1k.ops_s), ratio(praetor60.mib_s, wg60.mib_s)],
    fast: [ratio(fast1k.ops_s, wg1k.ops_s), ratio(fast60.mib_s, wg60.mib_s)],
    bolt: [ratio(bolt1k.ops_s, wg1k.ops_s), ratio(bolt60.mib_s, wg60.mib_s)],
  },
}, null, 2));
