// A small QR encoder for the pairing code: byte mode, error correction level M, versions 1-15, best mask by the
// standard penalty. Written for this extension (no third-party code, nothing loaded at runtime). Checked against
// segno's matrices in test/qr.test.mjs.

// Per version (index 1..15), level M: [EC codewords per block, [blocks, data codewords]...].
const BLOCKS_M = [null,
  [10, [1, 16]], [16, [1, 28]], [26, [1, 44]], [18, [2, 32]], [24, [2, 43]], [16, [4, 27]], [18, [4, 31]],
  [22, [2, 38], [2, 39]], [22, [3, 36], [2, 37]], [26, [4, 43], [1, 44]], [30, [1, 50], [4, 51]], [22, [6, 36], [2, 37]],
  [22, [8, 37], [1, 38]], [24, [4, 40], [5, 41]], [24, [5, 41], [5, 42]]];
const ALIGN = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
  [6, 30, 54], [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70]];

const dataCapacity = (v) => BLOCKS_M[v].slice(1).reduce((n, [b, d]) => n + b * d, 0);

// GF(256) with 0x11D, for Reed-Solomon.
const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const mul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);

function rsGenerator(n) {
  let g = [1];
  for (let i = 0; i < n; i++) {
    const next = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) { next[j] ^= g[j]; next[j + 1] ^= mul(g[j], EXP[i]); }
    g = next;
  }
  return g;
}

function rsRemainder(data, n) {
  const g = rsGenerator(n);
  const r = new Array(n).fill(0);
  for (const b of data) {
    const f = b ^ r.shift();
    r.push(0);
    for (let i = 0; i < n; i++) r[i] ^= mul(g[i + 1], f);
  }
  return r;
}

function codewords(bytes, v) {
  const bits = [];
  const put = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  put(4, 4);
  put(bytes.length, v < 10 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  const cap = dataCapacity(v) * 8;
  put(0, Math.min(4, cap - bits.length));
  while (bits.length % 8) bits.push(0);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  for (let pad = 0xec; data.length < dataCapacity(v); pad ^= 0xec ^ 0x11) data.push(pad);
  // Split into blocks, add EC, interleave.
  const [ec, ...groups] = BLOCKS_M[v];
  const blocks = [];
  let k = 0;
  for (const [count, len] of groups) for (let i = 0; i < count; i++) { const d = data.slice(k, k + len); k += len; blocks.push([d, rsRemainder(d, ec)]); }
  const out = [];
  const maxLen = Math.max(...blocks.map(([d]) => d.length));
  for (let i = 0; i < maxLen; i++) for (const [d] of blocks) if (i < d.length) out.push(d[i]);
  for (let i = 0; i < ec; i++) for (const [, e] of blocks) out.push(e[i]);
  return out;
}

const MASKS = [
  (x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, (x) => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

function build(v, cw, mask) {
  const size = v * 4 + 17;
  const m = Array.from({ length: size }, () => new Array(size).fill(false));
  const fn = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, dark) => { m[y][x] = dark; fn[y][x] = true; };
  // Finders with their separators.
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy;
      if (x < 0 || y < 0 || x >= size || y >= size) continue;
      const d = Math.max(Math.abs(dx), Math.abs(dy));
      set(x, y, d !== 2 && d !== 4);
    }
  }
  // Timing.
  for (let i = 8; i < size - 8; i++) { set(i, 6, i % 2 === 0); set(6, i, i % 2 === 0); }
  // Alignment.
  const pos = ALIGN[v];
  for (const ay of pos) for (const ax of pos) {
    if ((ax === 6 && ay === 6) || (ax === 6 && ay === pos[pos.length - 1]) || (ax === pos[pos.length - 1] && ay === 6)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  // Format (level M = 00) and the dark module.
  let rem = mask;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const fmt = ((mask << 10) | rem) ^ 0x5412;
  const bit = (val, i) => ((val >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) set(8, i, bit(fmt, i));
  set(8, 7, bit(fmt, 6)); set(8, 8, bit(fmt, 7)); set(7, 8, bit(fmt, 8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, bit(fmt, i));
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(fmt, i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(fmt, i));
  set(8, size - 8, true);
  // Version information (7 and up).
  if (v >= 7) {
    let r = v;
    for (let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1f25);
    const vb = (v << 12) | r;
    for (let i = 0; i < 18; i++) { const a = size - 11 + (i % 3), b = Math.floor(i / 3); set(a, b, bit(vb, i)); set(b, a, bit(vb, i)); }
  }
  // Data, zigzag from the bottom right; leftover modules stay light (the remainder bits).
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
      const x = right - j;
      const y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
      if (fn[y][x]) continue;
      if (i < cw.length * 8) { m[y][x] = bit(cw[i >>> 3], 7 - (i & 7)); i++; }
    }
  }
  const f = MASKS[mask];
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fn[y][x] && f(x, y)) m[y][x] = !m[y][x];
  m.fn = fn;
  return m;
}

function penalty(m) {
  const n = m.length;
  let p = 0;
  const lines = [];
  for (let y = 0; y < n; y++) { lines.push(m[y]); lines.push(m.map((row) => row[y])); }
  for (const line of lines) {
    let run = 1;
    for (let i = 1; i <= n; i++) {
      if (i < n && line[i] === line[i - 1]) run++;
      else { if (run >= 5) p += run - 2; run = 1; }
    }
    const s = line.map((b) => (b ? 1 : 0)).join("");
    for (const pat of ["10111010000", "00001011101"]) for (let k = s.indexOf(pat); k >= 0; k = s.indexOf(pat, k + 1)) p += 40;
  }
  for (let y = 0; y < n - 1; y++) for (let x = 0; x < n - 1; x++) {
    const c = m[y][x];
    if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) p += 3;
  }
  const dark = m.reduce((a, row) => a + row.filter(Boolean).length, 0);
  p += Math.floor(Math.abs(dark * 20 - n * n * 10) / (n * n)) * 10;
  return p;
}

/** Which modules are patterns, format or version (not data), for the tests. */
export function functionModules(v) {
  const size = v * 4 + 17;
  const m = build(v, new Array(dataCapacity(v) + BLOCKS_M[v][0] * BLOCKS_M[v].slice(1).reduce((n, [b]) => n + b, 0)).fill(0), 0);
  return { size, blocks: BLOCKS_M[v], isFunction: m.fn };
}

/** The QR for `text` as rows of booleans (true = dark), no quiet zone. `opts.version` / `opts.mask` force them (tests). */
export function encode(text, opts = {}) {
  const bytes = Array.from(new TextEncoder().encode(text));
  let v = opts.version;
  if (!v) for (v = 1; v <= 15; v++) if (bytes.length + (v < 10 ? 2 : 3) <= dataCapacity(v)) break;
  if (v > 15 || bytes.length + (v < 10 ? 2 : 3) > dataCapacity(v)) throw new Error("too long for a pairing QR");
  const cw = codewords(bytes, v);
  if (opts.mask !== undefined) return build(v, cw, opts.mask);
  let best = null, score = Infinity;
  for (let k = 0; k < 8; k++) { const m = build(v, cw, k); const s = penalty(m); if (s < score) { score = s; best = m; } }
  return best;
}

/** Draws the QR on a canvas with a 4-module quiet zone. */
export function draw(canvas, text, px = 6) {
  const m = encode(text);
  const n = m.length + 8;
  canvas.width = canvas.height = n * px;
  const g = canvas.getContext("2d");
  g.fillStyle = "#fff";
  g.fillRect(0, 0, n * px, n * px);
  g.fillStyle = "#000";
  m.forEach((row, y) => row.forEach((d, x) => { if (d) g.fillRect((x + 4) * px, (y + 4) * px, px, px); }));
}
