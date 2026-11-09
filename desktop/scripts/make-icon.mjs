import fs from 'node:fs';
import path from 'node:path';
import pngToIco from 'png-to-ico';
import { PNG } from 'pngjs';

const root = path.resolve(import.meta.dirname, '..');
const buildDir = path.join(root, 'build');
fs.mkdirSync(buildDir, { recursive: true });

const SIZE = 256;
const SS = 4;
const W = SIZE * SS;

function insideRoundedRect(x, y, x0, y0, x1, y1, radius) {
  const r = Math.min(radius, (x1 - x0) / 2, (y1 - y0) / 2);
  const cx = Math.max(x0 + r, Math.min(x, x1 - r));
  const cy = Math.max(y0 + r, Math.min(y, y1 - r));
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
}

function insidePolygon(x, y, points) {
  let inside = false;
  for (let i = 0, j = points.length - 1; i < points.length; j = i++) {
    const [xi, yi] = points[i];
    const [xj, yj] = points[j];
    if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

const pOuter = [
  [0.30, 0.25], [0.48, 0.25], [0.56, 0.27], [0.62, 0.33], [0.64, 0.40],
  [0.63, 0.47], [0.58, 0.53], [0.50, 0.56], [0.42, 0.56], [0.42, 0.75],
  [0.30, 0.75],
];
const pInner = [
  [0.42, 0.34], [0.48, 0.34], [0.52, 0.36], [0.54, 0.40], [0.53, 0.45],
  [0.50, 0.48], [0.42, 0.48],
];

const supersampled = new Float32Array(W * W * 4);

for (let y = 0; y < W; y++) {
  for (let x = 0; x < W; x++) {
    const nx = x / W;
    const ny = y / W;
    const i = (y * W + x) * 4;
    let r = 0;
    let g = 0;
    let b = 0;
    let a = 0;

    if (insideRoundedRect(nx, ny, 0.035, 0.035, 0.965, 0.965, 0.18)) {
      const vertical = Math.max(0, Math.min(1, ny));
      r = 7 + vertical * 4;
      g = 15 + vertical * 8;
      b = 17 + vertical * 7;
      a = 255;

      const glowDistance = Math.hypot(nx - 0.5, ny - 0.47);
      const glow = Math.max(0, 1 - glowDistance / 0.45) ** 2;
      r += glow * 14;
      g += glow * 45;
      b += glow * 37;

      const border = 0.026;
      const outer = insideRoundedRect(nx, ny, 0.035, 0.035, 0.965, 0.965, 0.18);
      const inner = insideRoundedRect(
        nx, ny,
        0.035 + border, 0.035 + border,
        0.965 - border, 0.965 - border,
        0.18 - border,
      );
      if (outer && !inner) {
        r = 54;
        g = 151;
        b = 124;
        a = 190;
      }
    }

    if (a > 0) {
      const gradient = Math.max(0, Math.min(1, (ny - 0.25) / 0.55));
      const pr = 124 - gradient * 66;
      const pg = 255 - gradient * 89;
      const pb = 201 - gradient * 54;

      if (insidePolygon(nx, ny, pOuter) && !insidePolygon(nx, ny, pInner)) {
        r = pr;
        g = pg;
        b = pb;
        a = 255;
      }

      if (Math.hypot(nx - 0.735, ny - 0.245) < 0.028) {
        r = 157;
        g = 255;
        b = 214;
        a = 255;
      }

      const rim = Math.abs(Math.hypot(nx - 0.5, ny - 0.5) - 0.405);
      if (rim < 0.0035 && nx > 0.12 && ny > 0.12) {
        r = 70;
        g = 148;
        b = 128;
        a = 90;
      }
    }

    supersampled[i] = r;
    supersampled[i + 1] = g;
    supersampled[i + 2] = b;
    supersampled[i + 3] = a;
  }
}

const png = new PNG({ width: SIZE, height: SIZE });
for (let y = 0; y < SIZE; y++) {
  for (let x = 0; x < SIZE; x++) {
    let r = 0;
    let g = 0;
    let b = 0;
    let a = 0;
    for (let sy = 0; sy < SS; sy++) {
      for (let sx = 0; sx < SS; sx++) {
        const i = (((y * SS + sy) * W) + (x * SS + sx)) * 4;
        r += supersampled[i];
        g += supersampled[i + 1];
        b += supersampled[i + 2];
        a += supersampled[i + 3];
      }
    }
    const count = SS * SS;
    const index = (y * SIZE + x) * 4;
    png.data[index] = Math.round(r / count);
    png.data[index + 1] = Math.round(g / count);
    png.data[index + 2] = Math.round(b / count);
    png.data[index + 3] = Math.round(a / count);
  }
}

const pngPath = path.join(buildDir, 'icon.png');
const icoPath = path.join(buildDir, 'icon.ico');
fs.writeFileSync(pngPath, PNG.sync.write(png));
const ico = await pngToIco(pngPath);
fs.writeFileSync(icoPath, ico);
console.log(`wrote ${path.relative(root, pngPath)} and ${path.relative(root, icoPath)} (${ico.length} bytes)`);
