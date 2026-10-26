// Sphinx's wire format, the laptop's half (the phone's is app/src/main/java/dev/sphinx/Crypto.kt; docs/DESIGN.md has both).
// WebCrypto only: X25519, HKDF-SHA256, HMAC-SHA256, AES-256-GCM. Same test vectors as the phone (test/vectors.json).

const te = new TextEncoder();

export function b64u(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64u(s) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export const random = (n) => crypto.getRandomValues(new Uint8Array(n));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
};

export async function hkdf(ikm, salt, info, len = 32) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: te.encode(info) }, k, len * 8));
}

export async function hmac(key, data) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

async function sha256hex(bytes) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function equal(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/**
 * A new pairing offer: the laptop's X25519 key pair, a pairing id, a 16-byte secret that only the QR carries. `relay`
 * is the relay's https origin; `token` the relay's registration token, when it requires one (it opens no key).
 */
export async function newOffer(relay, name, token = "") {
  const kp = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const offer = { pid: b64u(random(16)), laptop: b64u(pub), secret: b64u(random(16)), relay, name, token, priv };
  return { offer, qr: qrText(offer) };
}

export const qrText = (o) => `sphinx:1?p=${o.pid}&k=${o.laptop}&s=${o.secret}&r=${o.relay}&n=${encodeURIComponent(o.name)}${o.token ? `&t=${o.token}` : ""}`;

export const relayKey = (o) => hkdf(unb64u(o.secret), te.encode(o.pid), "sphinx relay v1");

/** The phone's hello, checked against the secret from the QR (the relay never saw it), then the two message keys. */
export async function finish(o, hello) {
  const h = unb64u(hello);
  if (h.length !== 64) throw new Error("bad hello");
  const phone = h.slice(0, 32), mac = h.slice(32);
  const hk = await hkdf(unb64u(o.secret), te.encode(o.pid), "sphinx hello v1");
  const want = await hmac(hk, te.encode(`sphinx hello v1|${o.pid}|${o.laptop}|${b64u(phone)}`));
  if (!equal(mac, want)) throw new Error("the hello isn't from the phone that scanned this QR");
  const priv = await crypto.subtle.importKey("jwk", o.priv, { name: "X25519" }, false, ["deriveBits"]);
  const pub = await crypto.subtle.importKey("raw", phone, { name: "X25519" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: pub }, priv, 256));
  if (shared.every((b) => b === 0)) throw new Error("bad phone key");
  const keys = await hkdf(shared, unb64u(o.secret), `sphinx v1|${o.pid}`, 64);
  shared.fill(0);
  return { pid: o.pid, relay: o.relay, l2p: b64u(keys.slice(0, 32)), p2l: b64u(keys.slice(32)), relayKey: b64u(await relayKey(o)), sent: 0, recv: 0 };
}

const aad = (pid, header) => concat(te.encode(`sphinx|${pid}|`), header);

function header(dir, ctr, exp) {
  const h = new Uint8Array(18);
  const v = new DataView(h.buffer);
  h[0] = 1; h[1] = dir.charCodeAt(0);
  v.setBigUint64(2, BigInt(ctr)); v.setBigUint64(10, BigInt(exp));
  return h;
}

export async function seal(key, pid, dir, ctr, exp, plain, iv = random(12)) {
  const k = await crypto.subtle.importKey("raw", unb64u(key), "AES-GCM", false, ["encrypt"]);
  const hd = header(dir, ctr, exp);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(pid, hd) }, k, plain));
  return b64u(concat(hd, iv, ct));
}

/** {ok, ctr, plain} or {ok: false, why}. Refused: wrong version or direction, a counter not above `last`, expired. */
export async function open(key, pid, dir, blob, last, now) {
  let b;
  try { b = unb64u(blob); } catch { return { ok: false, why: "malformed" }; }
  if (b.length < 46) return { ok: false, why: "malformed" };
  const v = new DataView(b.buffer, b.byteOffset);
  if (b[0] !== 1) return { ok: false, why: "version" };
  if (b[1] !== dir.charCodeAt(0)) return { ok: false, why: "direction" };
  const ctr = Number(v.getBigUint64(2)), exp = Number(v.getBigUint64(10));
  let plain;
  try {
    const k = await crypto.subtle.importKey("raw", unb64u(key), "AES-GCM", false, ["decrypt"]);
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(18, 30), additionalData: aad(pid, b.slice(0, 18)) }, k, b.slice(30)));
  } catch { return { ok: false, why: "bad seal" }; }
  if (ctr <= last) return { ok: false, why: "replay" };
  if (exp < now) return { ok: false, why: "expired" };
  if (exp > now + 120000) return { ok: false, why: "expiry too far out" };
  return { ok: true, ctr, plain };
}

/** The relay's HMAC headers for one request. */
export async function signed(p, method, path, query, body) {
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = b64u(random(16));
  const canon = `${method}\n${path}\n${query}\n${ts}\n${nonce}\n${await sha256hex(body)}`;
  return { "x-sphinx-pid": p.pid, "x-sphinx-ts": ts, "x-sphinx-nonce": nonce, "x-sphinx-sig": b64u(await hmac(unb64u(p.relayKey), te.encode(canon))) };
}

export async function signWith(relayKeyB64, method, path, query, ts, nonce, body) {
  const canon = `${method}\n${path}\n${query}\n${ts}\n${nonce}\n${await sha256hex(body)}`;
  return b64u(await hmac(unb64u(relayKeyB64), te.encode(canon)));
}

// ---- handoff file chunks: AES-256-GCM under the file's own key (sent only inside a sealed handoff.send) ----
// iv = 8 zero bytes + the chunk index (u32, big endian): unique per key, since every file gets a fresh random key.
// AAD "sphinx file v1|<fid>|<n>|<total>", so a chunk can't be moved to another file, place or length.
const chunkIv = (n) => { const iv = new Uint8Array(12); new DataView(iv.buffer).setUint32(8, n); return iv; };
const chunkAad = (fid, n, total) => te.encode(`sphinx file v1|${fid}|${n}|${total}`);

export async function sealChunk(keyB64, fid, n, total, plain) {
  const k = await crypto.subtle.importKey("raw", unb64u(keyB64), "AES-GCM", false, ["encrypt"]);
  return b64u(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: chunkIv(n), additionalData: chunkAad(fid, n, total) }, k, plain)));
}

/** The chunk's plaintext, or null when it isn't this file's chunk n of total. */
export async function openChunk(keyB64, fid, n, total, blob) {
  try {
    const k = await crypto.subtle.importKey("raw", unb64u(keyB64), "AES-GCM", false, ["decrypt"]);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: chunkIv(n), additionalData: chunkAad(fid, n, total) }, k, unb64u(blob)));
  } catch { return null; }
}

export const sha256Hex = (bytes) => sha256hex(bytes);
