import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { b64u, finish, newOffer, open, qrText, relayKey, seal, signWith, unb64u } from "../crypto.js";

const V = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url)));
const te = new TextEncoder(), td = new TextDecoder();
const offer = {
  pid: V.pid, laptop: V.laptop_pub, secret: V.secret, relay: "https://relay.example.com", name: "Chrome",
  priv: { kty: "OKP", crv: "X25519", d: V.laptop_priv, x: V.laptop_pub },
};

test("pairing derives the same keys as the Python vectors", async () => {
  assert.equal(qrText({ ...offer, pid: V.pid }), V.qr);
  const p = await finish(offer, V.hello);
  assert.equal(p.l2p, V.l2p);
  assert.equal(p.p2l, V.p2l);
  assert.equal(p.relayKey, V.relay);
  assert.equal(b64u(await relayKey(offer)), V.relay);
});

test("a hello not made with the QR's secret is refused", async () => {
  const bad = unb64u(V.hello); bad[40] ^= 1;
  await assert.rejects(finish(offer, b64u(bad)));
  await assert.rejects(finish({ ...offer, secret: b64u(new Uint8Array(16)) }, V.hello));
});

test("seal matches the vectors and open checks counter, direction and expiry", async () => {
  const r = V.request;
  assert.equal(await seal(V.l2p, V.pid, "q", r.ctr, r.exp, te.encode(r.plain), unb64u(r.iv)), r.blob);
  const ok = await open(V.p2l, V.pid, "r", V.reply.blob, 0, V.reply.exp - 30000);
  assert.ok(ok.ok);
  assert.equal(td.decode(ok.plain), V.reply.plain);
  assert.equal((await open(V.p2l, V.pid, "r", V.reply.blob, V.reply.ctr, V.reply.exp - 30000)).why, "replay");
  assert.equal((await open(V.p2l, V.pid, "r", V.reply.blob, 0, V.reply.exp + 1)).why, "expired");
  assert.equal((await open(V.p2l, V.pid, "r", V.reply.blob, 0, V.reply.exp - 200000)).why, "expiry too far out");
  assert.equal((await open(V.p2l, V.pid, "q", V.reply.blob, 0, V.reply.exp - 30000)).why, "direction");
  assert.equal((await open(V.l2p, V.pid, "r", V.reply.blob, 0, V.reply.exp - 30000)).why, "bad seal");
  assert.equal((await open(V.p2l, "x".repeat(22), "r", V.reply.blob, 0, V.reply.exp - 30000)).why, "bad seal");   // bound to the pairing
  const t = unb64u(V.reply.blob); t[t.length - 1] ^= 1;
  assert.equal((await open(V.p2l, V.pid, "r", b64u(t), 0, V.reply.exp - 30000)).why, "bad seal");
});

test("the relay signature matches the server's", async () => {
  const s = V.sign;
  assert.equal(await signWith(V.relay, s.method, s.path, s.query, s.ts, s.nonce, te.encode(s.body)), s.sig);
});

test("a fresh offer round-trips through a phone made here", async () => {
  const { offer: o, qr } = await newOffer("https://relay.example.com", "Work laptop");
  assert.match(qr, /^sphinx:1\?p=[\w-]{22}&k=[\w-]{43}&s=[\w-]{22}&r=https:\/\/relay\.example\.com&n=Work%20laptop$/);
  assert.match((await newOffer("https://relay.example.com", "L", "tok")).qr, /&n=L&t=tok$/);
  // The phone's side, in WebCrypto: its key, the shared secret, the hello.
  const kp = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const phone = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const { hkdf, hmac } = await import("../crypto.js");
  const hk = await hkdf(unb64u(o.secret), te.encode(o.pid), "sphinx hello v1");
  const hello = b64u(new Uint8Array([...phone, ...(await hmac(hk, te.encode(`sphinx hello v1|${o.pid}|${o.laptop}|${b64u(phone)}`)))]));
  const p = await finish(o, hello);
  const lap = await crypto.subtle.importKey("raw", unb64u(o.laptop), { name: "X25519" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: lap }, kp.privateKey, 256));
  const keys = await hkdf(shared, unb64u(o.secret), `sphinx v1|${o.pid}`, 64);
  assert.equal(p.l2p, b64u(keys.slice(0, 32)));
  const blob = await seal(p.l2p, p.pid, "q", 1, Date.now() + 60000, te.encode("hi"));
  assert.equal(td.decode((await open(b64u(keys.slice(0, 32)), p.pid, "q", blob, 0, Date.now())).plain), "hi");
});
