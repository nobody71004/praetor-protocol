// Render the VANTA vs WireGuard chart from measured JSON only.
// Usage: node bench/chart-vs-wireguard.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const vanta = JSON.parse(readFileSync(path.join(here, 'results-vanta.json'), 'utf8'));
const wg = JSON.parse(readFileSync(path.join(here, 'results-wireguard.json'), 'utf8'));

const vanta1k = vanta.cells.find((r) => r.size === 1008);
const vanta60 = vanta.cells.find((r) => r.size === 60000);
const wg1k = wg.transport.find((r) => r.size === 1024);
const wg60 = wg.transport.find((r) => r.size === 60000);

if (!vanta1k || !vanta60 || !wg1k || !wg60) throw new Error('benchmark rows missing');

const fmtInt = (n) => Math.round(n).toLocaleString('en-US');
const fmtOne = (n) => n.toFixed(1);
const ratio = (v, w) => (v / w).toFixed(2);

const W = 1040;
const H = 790;
const LEFT = 250;
const TRACK = 660;
const MINT = '#5ce1b0';
const BLUE = '#6aa9ff';
const INK = '#e7f2ea';
const MUTED = '#8fa6a1';
const GRID = '#22323a';

function panel(y, title, note, vantaValue, wgValue, format, unit) {
  const max = Math.max(vantaValue, wgValue) * 1.08;
  const vw = (vantaValue / max) * TRACK;
  const ww = (wgValue / max) * TRACK;
  const top = y + 42;
  return `
  <g>
    <text x="56" y="${y}" fill="${INK}" font-size="19" font-weight="700">${title}</text>
    <text x="56" y="${y + 22}" fill="${MUTED}" font-size="13">${note} · ${unit}</text>
    <rect x="${LEFT}" y="${top}" width="${TRACK}" height="34" rx="7" fill="#152027" stroke="${GRID}"/>
    <rect x="${LEFT}" y="${top}" width="${Math.max(2, vw)}" height="34" rx="7" fill="${MINT}"/>
    <text x="56" y="${top + 22}" fill="${INK}" font-size="15" font-weight="600">VANTA/1</text>
    <text x="${LEFT + Math.max(vw, 2) + 10}" y="${top + 22}" fill="${MINT}" font-size="15" font-weight="700">${format(vantaValue)}</text>

    <rect x="${LEFT}" y="${top + 52}" width="${TRACK}" height="34" rx="7" fill="#152027" stroke="${GRID}"/>
    <rect x="${LEFT}" y="${top + 52}" width="${Math.max(2, ww)}" height="34" rx="7" fill="${BLUE}"/>
    <text x="56" y="${top + 74}" fill="${INK}" font-size="15" font-weight="600">WireGuard</text>
    <text x="${LEFT + Math.max(ww, 2) + 10}" y="${top + 74}" fill="${BLUE}" font-size="15" font-weight="700">${format(wgValue)}</text>
    <text x="${W - 56}" y="${top + 22}" fill="${MUTED}" font-size="13" text-anchor="end">VANTA ${ratio(vantaValue, wgValue)}×</text>
  </g>`;
}

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-labelledby="title desc">
  <title id="title">VANTA/1 versus WireGuard on the same CPU</title>
  <desc id="desc">Grouped bar chart of handshakes per second, 1 KiB authenticated roundtrips per second, and 60 KB full-path throughput. WireGuard is boringtun userspace; VANTA is the Rust release build.</desc>
  <rect width="${W}" height="${H}" fill="#0b0f12"/>
  <text x="56" y="62" fill="${INK}" font-size="30" font-weight="800" letter-spacing="-0.5">VANTA/1 vs WireGuard</text>
  <text x="56" y="92" fill="${MUTED}" font-size="14">Same machine · single thread · Rust release builds · higher is better</text>
  <g font-family="Segoe UI, Arial, sans-serif">
    <rect x="${W - 214}" y="46" width="14" height="14" rx="3" fill="${MINT}"/>
    <text x="${W - 192}" y="58" fill="${INK}" font-size="13">VANTA/1 Rust</text>
    <rect x="${W - 214}" y="70" width="14" height="14" rx="3" fill="${BLUE}"/>
    <text x="${W - 192}" y="82" fill="${INK}" font-size="13">WireGuard (boringtun)</text>
  </g>
  <line x1="56" y1="116" x2="${W - 56}" y2="116" stroke="${GRID}"/>
  ${panel(156, 'Handshakes per second', 'complete Noise / hybrid handshake', vanta.handshake_ops_s, wg.handshake_ops_s, fmtInt, 'ops/s')}
  ${panel(356, '1 KiB authenticated roundtrips', 'one cell or one WireGuard transport packet', vanta1k.ops_s, wg1k.ops_s, fmtInt, 'roundtrips/s')}
  ${panel(556, '60 KB full-path throughput', 'fixed-cell framing vs WireGuard transport packet', vanta60.mib_s, wg60.mib_s, fmtOne, 'MiB/s')}
  <text x="56" y="750" fill="${MUTED}" font-size="12">VANTA includes two-pass SIV, a 32-byte commitment tag, 80-byte fixed-cell framing and an ML-KEM-768 hybrid handshake.</text>
  <text x="56" y="768" fill="${MUTED}" font-size="12">WireGuard is Cloudflare boringtun 0.7.1 userspace (NoiseIK, X25519, ChaCha20-Poly1305); no TUN/UDP, so these are protocol CPU costs, not VPN wall-clock.</text>
</svg>
`;

const out = path.join(here, '..', 'docs', 'benchmarks-vanta-vs-wireguard.svg');
writeFileSync(out, svg);
console.log(`wrote ${out}`);
console.log(JSON.stringify({
  handshakes: [vanta.handshake_ops_s, wg.handshake_ops_s],
  roundtrip_1k: [vanta1k.ops_s, wg1k.ops_s],
  throughput_60k: [vanta60.mib_s, wg60.mib_s],
}, null, 2));
