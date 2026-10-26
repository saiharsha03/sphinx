import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { encode, functionModules } from "../qr.js";

// segno (Python) made these with the same version and mask. Two encoders may pad differently, so the data area can
// differ; what must match exactly is every pattern, the format and the version bits. The data is then read back here
// with an independent reader: unmask, zigzag, de-interleave, Reed-Solomon syndromes zero, byte mode gives the text.
// (Both encoders' matrices were also decoded by zxing-cpp once, 2026-10-21: all eight read back.)
const cases = JSON.parse(readFileSync(new URL("./qr_vectors.json", import.meta.url)));

const EXP = [], LOG = [];
for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
const gmul = (a, b) => (a && b ? EXP[(LOG[a] + LOG[b]) % 255] : 0);
const MASKS = [(x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, (x) => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0];

function readBack(m, v, mask) {
  const { size, blocks, isFunction } = functionModules(v);
  const bits = [];
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
      const x = right - j, y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
      if (!isFunction[y][x]) bits.push(m[y][x] !== MASKS[mask](x, y) ? 1 : 0);
    }
  }
  const cw = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) cw.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  const [ec, ...groups] = blocks;
  const lens = groups.flatMap(([n, d]) => new Array(n).fill(d));
  const data = lens.map(() => []), eccs = lens.map(() => []);
  let k = 0;
  for (let i = 0; i < Math.max(...lens); i++) lens.forEach((l, b) => { if (i < l) data[b].push(cw[k++]); });
  for (let i = 0; i < ec; i++) lens.forEach((_, b) => eccs[b].push(cw[k++]));
  lens.forEach((_, b) => {
    const word = [...data[b], ...eccs[b]];
    for (let r = 0; r < ec; r++) {   // syndrome S_r = word(alpha^r)
      let s = 0;
      for (const c of word) s = gmul(s, EXP[r]) ^ c;
      assert.equal(s, 0, `block ${b} syndrome ${r}`);
    }
  });
  const all = data.flat();
  const stream = all.flatMap((b) => [7, 6, 5, 4, 3, 2, 1, 0].map((i) => (b >> i) & 1));
  const take = (n) => stream.splice(0, n).reduce((a, b) => (a << 1) | b, 0);
  assert.equal(take(4), 4, "byte mode");
  const len = take(v < 10 ? 8 : 16);
  return new TextDecoder().decode(new Uint8Array(Array.from({ length: len }, () => take(8))));
}

test("patterns, format and version bits match segno; the data reads back with valid Reed-Solomon", () => {
  for (const c of cases) {
    const m = encode(c.text, { version: c.version, mask: c.mask });
    const { isFunction } = functionModules(c.version);
    m.forEach((row, y) => row.forEach((d, x) => { if (isFunction[y][x]) assert.equal(d ? "1" : "0", c.rows[y][x], `v${c.version} (${x},${y})`); }));
    assert.equal(readBack(m, c.version, c.mask), c.text);
    // segno's own matrix reads back the same way, so the reader isn't just agreeing with the encoder.
    assert.equal(readBack(c.rows.map((r) => [...r].map((ch) => ch === "1")), c.version, c.mask), c.text);
  }
});

test("picks the smallest version that fits and refuses what doesn't", () => {
  assert.equal(encode("hello").length, 21);
  const qr = cases.find((c) => c.version === 9).text;
  assert.ok(encode(qr).length <= 57);
  assert.throws(() => encode("x".repeat(500)));
});
