import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Handoff on the laptop: what may be sent, what an arrival may be, and that nothing acts without the popup's click.
const PSL = readFileSync(new URL("../public_suffix_list.dat", import.meta.url), "utf8");
const V = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const RELAY = "https://relay.example.com";
const store = {}, session = {}, calls = [], opened = [], notes = [], files = new Map();
let outbox = [], listener;
globalThis.chrome = {
  runtime: {
    id: "sphinx", getURL: (p) => `chrome-extension://sphinx/${p}`, getManifest: () => ({ host_permissions: [] }),
    onMessage: { addListener: (f) => { listener = f; } }, onStartup: { addListener() {} }, onInstalled: { addListener() {} },
  },
  storage: {
    local: { setAccessLevel: async () => {}, get: async (k) => ({ [k]: store[k] }), set: async (o) => Object.assign(store, structuredClone(o)), remove: async (ks) => [].concat(ks).forEach((k) => delete store[k]) },
    session: { get: async (k) => ({ [k]: session[k] }), set: async (o) => Object.assign(session, structuredClone(o)) },
  },
  permissions: { getAll: async () => ({ origins: [] }), remove: async () => true, onRemoved: { addListener() {} } },
  scripting: { registerContentScripts: async () => {}, unregisterContentScripts: async () => {} },
  action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setTitle: async () => {}, setIcon: async () => {} },
  tabs: { create: async (o) => { opened.push(o.url); }, onUpdated: { addListener() {} }, onRemoved: { addListener() {} } },
  alarms: { create: async () => {}, clear: async () => {}, onAlarm: { addListener() {} } },
  contextMenus: { removeAll: (f) => f(), create: () => {}, onClicked: { addListener() {} } },
  notifications: { create: (id, o) => notes.push(o.message), onClicked: { addListener() {} } },
};
globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  if (u.startsWith("chrome-extension://")) return { text: async () => PSL };
  const path = new URL(u).pathname;
  calls.push([init.method, path, init.body ? JSON.parse(new TextDecoder().decode(init.body)) : null]);
  const ok = (j) => ({ status: 200, ok: true, json: async () => j });
  if (path === "/v1/outbox" && init.method === "GET") return ok({ items: outbox });
  if (path.startsWith("/v1/files/") && init.method === "PUT") { files.set(path, calls.at(-1)[2].blob); return ok({ ok: true }); }
  if (path.startsWith("/v1/files/") && init.method === "GET") return files.has(path) ? ok({ blob: files.get(path) }) : { status: 404, ok: false };
  return ok({ ok: true, queued: true, acked: 0 });
};
const { _test } = await import("../background.js");
const { b64u, seal, open, sealChunk, openChunk, sha256Hex, unb64u } = await import("../crypto.js");
const H = await import("../handoff.js");

const ask = (m, sender) => new Promise((ok) => { listener(m, sender, ok) || ok(undefined); });
const POPUP = { id: "sphinx", url: "chrome-extension://sphinx/popup.html", origin: "chrome-extension://sphinx" };
const pairing = () => ({ pid: "P".repeat(22), relay: RELAY, relayKey: "A".repeat(43), l2p: "A".repeat(43), p2l: "B".repeat(43), sent: 0, recv: 0 });
/** The phone's sealed handoff (direction 'p', its own counter), as the relay's outbox hands it over. */
const fromPhone = async (rid, body, ctr, kind = "handoff.send", dir = "p") =>
  ({ rid, blob: await seal(store.pairing.p2l, store.pairing.pid, dir, ctr, Date.now() + 100000, new TextEncoder().encode(JSON.stringify({ v: 1, kind, rid, body }))) });

test("links are http(s) only; text and files have caps; names can't climb out of the folder", () => {
  for (const u of ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "chrome://settings", "https://u:p@example.com/", "", "x".repeat(3000)])
    assert.equal(H.httpUrl(u), null, u);
  assert.equal(H.httpUrl("https://example.com/a?b=1"), "https://example.com/a?b=1");
  assert.equal(H.item({ type: "link", url: "javascript:alert(1)" }), null);
  assert.equal(H.item({ type: "text", text: "é".repeat(1501) }), null);            // 3002 bytes of UTF-8
  assert.equal(H.item({ type: "text", text: "  " }), null);
  assert.equal(H.safeName("../../etc/passwd"), "passwd");
  assert.equal(H.safeName("C:\\Users\\x\\..\\evil.exe"), "evil.exe");
  assert.equal(H.safeName("...hidden"), "hidden");
  assert.equal(H.safeName("a\u0000b\nc"), "abc");
  const f = { fid: "F".repeat(22), key: "K".repeat(43), name: "a.pdf", mime: "application/pdf", size: H.CHUNK + 1, chunks: 2, sha256: "0".repeat(64) };
  assert.equal(H.item({ type: "file", file: f }).file.chunks, 2);
  assert.equal(H.item({ type: "file", file: { ...f, chunks: 3 } }), null);         // chunks must fit the size
  assert.equal(H.item({ type: "file", file: { ...f, size: H.MAX_FILE + 1, chunks: 17 } }), null);
  assert.equal(H.item({ type: "file", file: { ...f, mime: "text/html; x" } }).file.mime, "application/octet-stream");
  assert.equal(H.item({ type: "shell", cmd: "rm" }), null);
});

test("a file chunk matches the vector made by pyca/cryptography, and nothing else opens it", async () => {
  const f = V.file;
  assert.equal(await sealChunk(f.key, f.fid, f.n, f.total, unb64u(f.plain)), f.blob);
  assert.deepEqual(await openChunk(f.key, f.fid, f.n, f.total, f.blob), unb64u(f.plain));
  assert.equal(await openChunk(f.key, f.fid, 0, f.total, f.blob), null);           // another place
  assert.equal(await openChunk(f.key, f.fid, f.n, 4, f.blob), null);               // another length
  assert.equal(await openChunk(f.key, "G".repeat(22), f.n, f.total, f.blob), null); // another file
  // The phone's push direction 'p' matches its vector too.
  const o = await open(V.p2l, V.pid, "p", V.push.blob, 0, V.push.exp - 1000);
  assert.equal(new TextDecoder().decode(o.plain), V.push.plain);
  assert.equal((await open(V.p2l, V.pid, "r", V.push.blob, 0, V.push.exp - 1000)).why, "direction");
});

test("what the phone sends is listed and announced, never opened; its counter is its own", async () => {
  store.pairing = pairing();
  outbox = [await fromPhone("H".repeat(22), { type: "link", url: "https://example.com/x", open: true }, 1),
    await fromPhone("I".repeat(22), { type: "link", url: "javascript:alert(1)" }, 2),
    await fromPhone("J".repeat(22), { type: "text", text: "hello" }, 3)];
  const r = await ask({ t: "inbox" }, POPUP);
  assert.deepEqual(r.items.map((x) => x.type + ":" + (x.url || x.text)), ["text:hello", "link:https://example.com/x"]);
  assert.equal(opened.length, 0);                                    // nothing opened on arrival
  assert.equal(notes.length, 2);
  assert.equal(store.pairing.pushRecv, 3);
  assert.equal(store.pairing.recv, 0);                               // the replies' counter is untouched
  assert.ok(calls.some(([m, p, b]) => m === "POST" && p === "/v1/outbox/ack" && b.rids.length === 3));
  // The same blobs again (a replay) add nothing.
  assert.equal((await ask({ t: "inbox" }, POPUP)).items.length, 2);
  // A reply-direction blob or a code reply in the outbox is not a handoff.
  outbox = [await fromPhone("K".repeat(22), { type: "text", text: "x" }, 9, "handoff.send", "r"), await fromPhone("L".repeat(22), { ok: true, code: "123456" }, 10, "code.reply")];
  assert.equal((await ask({ t: "inbox" }, POPUP)).items.length, 2);
  outbox = [];
});

test("a link opens only on the popup's Open, and only from the popup", async () => {
  const id = "H".repeat(22);
  const content = { id: "sphinx", tab: { id: 1, url: "https://github.com/" }, url: "https://github.com/", frameId: 0, documentId: "d" };
  assert.equal((await ask({ t: "openLink", id }, content)).ok, false);
  assert.equal((await ask({ t: "openLink", id }, { ...POPUP, url: "https://evil.example/popup.html", origin: "https://evil.example" })).ok, false);
  assert.equal(opened.length, 0);
  assert.equal((await ask({ t: "openLink", id }, POPUP)).ok, true);
  assert.deepEqual(opened, ["https://example.com/x"]);
  assert.equal((await ask({ t: "inbox" }, POPUP)).items.length, 2);  // it stays listed until he removes it (1.3.0)
});

test("sending: a link, a text, the right-click menu, and a file in chunks under its own key", async () => {
  store.pairing = pairing(); calls.length = 0;
  assert.equal((await ask({ t: "sendLink", url: "file:///etc/passwd", open: true }, POPUP)).ok, false);
  assert.equal((await ask({ t: "sendLink", url: "https://example.com/p", open: true }, POPUP)).ok, true);
  assert.equal((await _test.menuClicked({ menuItemId: "sphinx.text", selectionText: "picked words" })).ok, true);
  const sent = calls.filter(([m, p]) => m === "POST" && p === "/v1/requests");
  assert.equal(sent.length, 2);
  // Sealed laptop-to-phone like a code request: the phone opens it with l2p, 'q'.
  const env = JSON.parse(new TextDecoder().decode((await open(store.pairing.l2p, store.pairing.pid, "q", sent[0][2].blob, 0, Date.now())).plain));
  assert.deepEqual([env.kind, env.body], ["handoff.send", { type: "link", url: "https://example.com/p", open: true }]);
  // A file: chunks first (ciphertext only), then the handoff carrying the key and the hash.
  const data = new Uint8Array(H.CHUNK + 10).map((_, i) => i % 251);
  let s = ""; for (let i = 0; i < data.length; i += 0x8000) s += String.fromCharCode(...data.subarray(i, i + 0x8000));
  calls.length = 0;
  assert.equal((await ask({ t: "sendFile", name: "../x.bin", mime: "application/octet-stream", data: btoa(s) }, POPUP)).ok, true);
  const puts = calls.filter(([m]) => m === "PUT");
  assert.deepEqual(puts.map(([, p]) => p.split("/").pop()), ["0", "1"]);
  const fenv = JSON.parse(new TextDecoder().decode((await open(store.pairing.l2p, store.pairing.pid, "q", calls.at(-1)[2].blob, 0, Date.now())).plain));
  const f = fenv.body.file;
  assert.equal(f.name, "x.bin"); assert.equal(f.size, data.length); assert.equal(f.sha256, await sha256Hex(data));
  assert.ok(!puts.some(([, , b]) => b.blob.includes(f.key)));
  // And back down, as the laptop fetches a file from the phone: whole, checked, then deleted.
  assert.deepEqual(await _test.fetchFile(f), data);
  await assert.rejects(_test.fetchFile({ ...f, sha256: "0".repeat(64) }));
  assert.equal((await ask({ t: "sendFile", name: "empty", data: "" }, POPUP)).ok, false);
});

test("a received file downloads only through the popup, and must match its hash", async () => {
  store.pairing = pairing(); store.inbox = [];
  const key = b64u(crypto.getRandomValues(new Uint8Array(32))), fid = "Q".repeat(22), data = new TextEncoder().encode("from the phone");
  files.set(`/v1/files/${fid}/0`, await sealChunk(key, fid, 0, 1, data));
  outbox = [await fromPhone("M".repeat(22), { type: "file", file: { fid, key, name: "note.txt", mime: "text/plain", size: data.length, chunks: 1, sha256: await sha256Hex(data) } }, 20)];
  const it = (await ask({ t: "inbox" }, POPUP)).items.find((x) => x.type === "file");
  outbox = [];
  assert.equal(it.file.name, "note.txt");
  const r = await ask({ t: "file", id: it.id }, POPUP);
  assert.equal(atob(r.data), "from the phone");
  // Not marked and still on the relay until the popup says the download started.
  assert.ok(!calls.some(([m, p]) => m === "DELETE" && p === `/v1/files/${fid}`));
  assert.notEqual(store.inbox.find((x) => x.id === it.id).saved, true);
  assert.equal((await ask({ t: "saved", id: it.id, downloadId: 7 }, POPUP)).ok, true);
  // Marked, and gone from the relay, only once Chrome reports that download complete; an interrupted one changes nothing.
  await _test.downloaded({ id: 7, state: { current: "interrupted" } });
  assert.notEqual(store.inbox.find((x) => x.id === it.id).saved, true);
  assert.equal((await ask({ t: "saved", id: it.id, downloadId: 8 }, POPUP)).ok, true);
  await _test.downloaded({ id: 8, state: { current: "complete" } });
  assert.ok(calls.some(([m, p]) => m === "DELETE" && p === `/v1/files/${fid}`));
  assert.equal(store.inbox.find((x) => x.id === it.id).saved, true);   // kept, marked
});
