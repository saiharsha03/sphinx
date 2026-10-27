import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// A small stand-in for the chrome APIs the service worker uses; the relay is a fetch that records calls.
const PSL = readFileSync(new URL("../public_suffix_list.dat", import.meta.url), "utf8");
// The pairing's relay, granted on the options page; Chrome keeps it as the canonical https://host/*.
const RELAY = "https://relay.example.com";
const RELAY_PERM = `${RELAY}/*`;
const store = {}, calls = [], removed = [], registered = [], order = [], badge = {};
let granted = [RELAY_PERM], listener;
// What the relay answers to GET /status and GET /replies/{rid} (a sealed blob), per test.
let relayStatus = null, replyBlob = null;
globalThis.chrome = {
  runtime: {
    id: "sphinx", getURL: (p) => `chrome-extension://sphinx/${p}`, getManifest: () => ({ host_permissions: [] }),
    onMessage: { addListener: (f) => { listener = f; } }, onStartup: { addListener() {} }, onInstalled: { addListener() {} },
  },
  storage: { local: {
    // Resolves a tick later, as Chrome's does: nothing may touch storage or register a script before it settles.
    setAccessLevel: async (o) => { await new Promise((r) => setTimeout(r, 5)); order.push(`access:${o.accessLevel}`); },
    get: async (k) => { order.push("get"); return { [k]: store[k] }; },
    set: async (o) => { order.push("set"); Object.assign(store, structuredClone(o)); },
    remove: async (ks) => { order.push("remove"); [].concat(ks).forEach((k) => delete store[k]); },
  }, session: { get: async () => ({}), set: async () => {} } },
  permissions: {
    getAll: async () => ({ origins: [...granted] }),
    remove: async ({ origins }) => { removed.push(...origins); granted = granted.filter((o) => !origins.includes(o)); return true; },
    onRemoved: { addListener() {} },
  },
  scripting: { registerContentScripts: async (s) => { order.push("register"); registered.push(...s); }, unregisterContentScripts: async () => {} },
  action: {
    setBadgeText: async ({ text }) => { badge.text = text; }, setBadgeBackgroundColor: async ({ color }) => { badge.color = color; },
    setTitle: async ({ title, tabId }) => { if (tabId === undefined) badge.title = title; else (badge.tabs ??= {})[tabId] = title; },
    setIcon: async () => { throw new Error("no OffscreenCanvas in node"); }, onClicked: { addListener() {} },
  },
};
let pslFails = 0, hello = null, helloGate = null, fetchGate = null;
globalThis.fetch = async (url, init = {}) => {
  if (String(url).startsWith("chrome-extension://")) {
    if (pslFails > 0) { pslFails--; throw new Error("not yet"); }
    return { text: async () => PSL };
  }
  calls.push([String(url), init.method, init.body]);
  if (fetchGate) await fetchGate;   // a slow relay (a long poll), held until a test lets it go
  if (String(url).endsWith("/v1/hello")) {
    if (helloGate) await helloGate;
    return { status: 200, ok: true, json: async () => ({ hello }) };
  }
  if (String(url).endsWith("/v1/status")) {
    if (!relayStatus) throw new Error("offline");
    return { status: 200, ok: true, json: async () => relayStatus };
  }
  if (String(url).includes("/v1/replies/")) {
    if (!replyBlob) return { status: 204, ok: true };
    const b = typeof replyBlob === "function" ? await replyBlob(String(url).split("/").pop()) : replyBlob; replyBlob = null;
    return { status: 200, ok: true, json: async () => ({ blob: b }) };
  }
  return { status: 200, ok: true, json: async () => ({ queued: true }) };
};
const { _test, canonical, phoneState, dotState, heldCodes, heldNow, heldFor, offerFresh, windowFresh, windowAfter, shape, KEEPALIVE_MS } = await import("../background.js");
const { b64u, hkdf, hmac, open, seal, unb64u } = await import("../crypto.js");

const ask = (m, sender) => new Promise((ok) => { listener(m, sender, ok) || ok(undefined); });
const tab = (url, id = 1, frame = url, doc = "doc-1", frameId = 0) => ({ id: "sphinx", tab: { id, url }, url: frame, frameId, documentId: doc });
// As Chrome sends it: options_page opens in a tab, so the sender has one, and its origin is the extension's.
const optionsPage = { id: "sphinx", url: "chrome-extension://sphinx/options.html", origin: "chrome-extension://sphinx", tab: { id: 7 }, frameId: 0, documentId: "opt" };
const pairing = () => ({ pid: "P".repeat(22), relay: RELAY, relayKey: "A".repeat(43), l2p: "A".repeat(43), p2l: "B".repeat(43), sent: 0, recv: 0 });

store.pairing = pairing();
store.domains = { list: ["github.com", "gitlab.com"], groups: [["github.com"], ["gitlab.com"]], at: 1 };

test("storage is closed to content scripts before anything reads it, writes it or registers a script", async () => {
  await ask({ t: "eligible" }, tab("https://github.com/x"));
  await _test.register();
  assert.equal(order[0], "access:TRUSTED_CONTEXTS");
  assert.equal(order.filter((o) => o.startsWith("access:")).length, 1);
  assert.ok(order.indexOf("get") > 0);
});

test("the content scripts never touch storage, and are registered for this session only", async () => {
  for (const f of ["content.js", "detect.js"]) assert.doesNotMatch(readFileSync(new URL(`../${f}`, import.meta.url), "utf8"), /chrome\s*\.\s*storage|storage\s*\.\s*(local|sync|session)/, f);
  granted = [RELAY_PERM, "https://github.com/*"]; registered.length = 0;
  await _test.register();
  assert.equal(registered[0].persistAcrossSessions, false);
});

test("only a saved https site may ask, top and frame on the same account; the site comes from Chrome", async () => {
  assert.equal((await ask({ t: "eligible" }, tab("https://github.com/x"))).ok, true);
  for (const s of [tab("https://github.com.evil.io/"), tab("http://github.com/"), tab("https://gist.github.com/"), tab("https://github.com/", 1, "https://evil.io/frame"),
    tab("https://github.com/", 1, "https://gitlab.com/frame"), tab("https://evilgithub.com/")])
    assert.equal((await ask({ t: "eligible" }, s)).ok, false, s.tab.url + " " + s.url);
  const before = calls.length;
  assert.equal((await ask({ t: "ask", host: "github.com" }, tab("https://evil.io/"))).ok, false);   // a host in the message is ignored
  assert.equal(calls.length, before);
});

test("a request is bound to its document, frame, origins and pairing", async () => {
  const r = await ask({ t: "ask", user: "x".repeat(500) }, tab("https://github.com/login", 7, "https://github.com/login", "doc-A"));
  assert.ok(r.ok && /^[\w-]{22}$/.test(r.rid));
  const no = { done: true, ok: false, why: "no such request" };
  assert.deepEqual(await ask({ t: "wait", rid: r.rid }, tab("https://github.com/login", 8, "https://github.com/login", "doc-A")), no);      // another tab
  assert.deepEqual(await ask({ t: "wait", rid: r.rid }, tab("https://github.com/login", 7, "https://github.com/login", "doc-B")), no);      // it navigated
  assert.deepEqual(await ask({ t: "wait", rid: r.rid }, tab("https://github.com/login", 7, "https://github.com/login", "doc-A", 3)), no);   // another frame
  assert.deepEqual(await ask({ t: "wait", rid: "../../hello" }, tab("https://github.com/", 7, "https://github.com/", "doc-A")), no);
  // The same document asking again gets the same request, not a second one.
  const again = await ask({ t: "ask" }, tab("https://github.com/login", 7, "https://github.com/login", "doc-A"));
  assert.equal(again.rid, r.rid);
  // A new document in the same tab is a new request; the old one is no longer its to wait on.
  const fresh = await ask({ t: "ask" }, tab("https://github.com/login", 7, "https://github.com/login", "doc-C"));
  assert.notEqual(fresh.rid, r.rid);
  // An unpair and re-pair on the same document voids what it was waiting on.
  store.pairing = { ...pairing(), pid: "Q".repeat(22) };
  assert.deepEqual(await ask({ t: "wait", rid: fresh.rid }, tab("https://github.com/login", 7, "https://github.com/login", "doc-C")), no);
  store.pairing = pairing();
});

test("counters never repeat under concurrent sends", async () => {
  store.pairing = pairing();
  await Promise.all(Array.from({ length: 12 }, () => _test.send("domains.request", {})));
  assert.equal(store.pairing.sent, 12);
  const order = [];
  await Promise.all([_test.locked(async () => { await new Promise((r) => setTimeout(r, 20)); order.push(1); }), _test.locked(async () => order.push(2))]);
  assert.deepEqual(order, [1, 2]);
});

test("register keeps the required relay permission and runs only on exact granted sites, top frame", async () => {
  granted = [RELAY_PERM, "https://github.com/*", "https://www.github.com/*", "https://old.example/*", "https://*.github.com/*"];
  removed.length = 0; registered.length = 0;
  const matches = await _test.register();
  assert.ok(!removed.includes(RELAY_PERM));
  assert.deepEqual(removed.sort(), ["https://*.github.com/*", "https://old.example/*"]);
  assert.deepEqual(matches, ["https://github.com/*", "https://www.github.com/*"]);
  assert.equal(registered[0].allFrames, false);
  assert.deepEqual(registered[0].matches, ["https://github.com/*", "https://www.github.com/*"]);
});

test("permission patterns are compared the way Chrome keeps them", () => {
  assert.equal(canonical(`${RELAY}/v1/*`), RELAY_PERM);
  assert.equal(canonical("https://*.example.com/a/b*"), "https://*.example.com/*");
  assert.equal(canonical("https://github.com/*"), "https://github.com/*");
});

// The phone's side of a hello for whatever offer is current, made with WebCrypto like crypto.test does.
async function phoneHello() {
  const o = store.offer;
  const kp = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const hk = await hkdf(unb64u(o.secret), new TextEncoder().encode(o.pid), "sphinx hello v1");
  const mac = await hmac(hk, new TextEncoder().encode(`sphinx hello v1|${o.pid}|${o.laptop}|${b64u(pub)}`));
  return b64u(new Uint8Array([...pub, ...mac]));
}
const gate = () => { let open; helloGate = new Promise((r) => { open = r; }); return () => { helloGate = null; open(); }; };

test("a hello that arrives after an unpair doesn't bring the pairing back", async () => {
  delete store.pairing;
  await _test.options({ t: "offer", name: "L", relay: RELAY });
  hello = await phoneHello();
  const release = gate();
  const late = _test.options({ t: "hello" });
  await new Promise((r) => setTimeout(r, 10));
  await _test.options({ t: "unpair" });
  release();
  assert.equal((await late).paired, false);
  assert.equal(store.pairing, undefined);
});

test("overlapping or stale hellos never roll counters back, and a newer offer wins", async () => {
  delete store.pairing;
  await _test.options({ t: "offer", name: "L", relay: RELAY });
  hello = await phoneHello();
  const release = gate();
  const first = _test.options({ t: "hello" }), second = _test.options({ t: "hello" });
  await new Promise((r) => setTimeout(r, 10));
  release();
  await Promise.all([first, second]);
  const pid = store.pairing.pid;
  store.pairing = { ...store.pairing, sent: 3, recv: 7 };
  // Another hello for the same (consumed) offer changes nothing.
  assert.equal((await _test.options({ t: "hello" })).paired, true);
  assert.equal(store.pairing.pid, pid);
  assert.deepEqual([store.pairing.sent, store.pairing.recv], [3, 7]);
  // An offer replaced while its hello was on the way: refused.
  delete store.pairing;
  await _test.options({ t: "offer", name: "A", relay: RELAY });
  hello = await phoneHello();
  const old = { ...store.offer };
  const release2 = gate();
  const late = _test.options({ t: "hello" });
  await new Promise((r) => setTimeout(r, 10));
  await _test.options({ t: "offer", name: "B", relay: RELAY });
  release2();
  assert.equal((await late).paired, false);
  assert.equal(store.pairing, undefined);
  assert.notEqual(store.offer.gen, old.gen);
});

test("a failed suffix list load is retried, not cached", async () => {
  // A fresh worker: the first fetch fails, the next one works.
  pslFails = 1;
  const mod = await import("../background.js?again");
  await assert.rejects(mod._test.ready());
  await mod._test.ready();
});

test("pairing and unpairing come from the options page only", async () => {
  store.pairing = pairing();
  for (const t of ["offer", "unpair", "refresh", "granted", "status", "hello"])
    assert.equal((await ask({ t }, tab("https://github.com/"))).ok, false, t);
  assert.ok(store.pairing);
  assert.equal((await ask({ t: "status" }, { id: "another-extension", url: "chrome-extension://sphinx/options.html" })), undefined);
  assert.equal((await ask({ t: "status" }, optionsPage)).paired, true);
  // A page can't pose as it: Chrome's origin is the page's, whatever URL it names.
  assert.equal((await ask({ t: "status" }, { ...tab("https://github.com/"), url: "chrome-extension://sphinx/options.html", origin: "https://github.com" })).paired, undefined);
  granted = [RELAY_PERM]; removed.length = 0;
  assert.equal((await ask({ t: "unpair" }, optionsPage)).ok, true);
  assert.equal(store.pairing, undefined);
  assert.deepEqual(removed, [RELAY_PERM]);                 // unpaired, the relay grant goes too
  // The options page in its own tab (how options_page opens) gets a pairing code.
  assert.match((await ask({ t: "offer", name: "Laptop", relay: RELAY }, optionsPage)).qr, /^sphinx:1\?.*&r=https:\/\/relay\.example\.com&n=Laptop$/);
  store.offer = undefined;
  assert.equal(store.pairing, undefined);
});

// ---- 1.0.5 (owner, 2026-10-25): texted codes, asking again after expiry, the pairing badge ----

/** The phone's sealed answer to `rid`, as the relay would hand it back. */
async function phoneReply(rid, body, ctr, kind = "code.reply") {
  const p = store.pairing;
  const env = new TextEncoder().encode(JSON.stringify({ v: 1, kind, rid, body }));
  return seal(p.p2l, p.pid, "r", ctr, Date.now() + 60000, env);
}
const page = (doc) => {
  store.domains = { list: ["github.com"], groups: [["github.com"]], at: 1 };   // an unpair above dropped them
  return tab("https://github.com/login", 9, "https://github.com/login", doc);
};

test("a texted code (via text) may be 4 digits and comes back marked so it isn't submitted", async () => {
  store.pairing = pairing();
  const r = await ask({ t: "ask", user: "w" }, page("doc-T1"));
  replyBlob = await phoneReply(r.rid, { ok: true, code: "4829", account: "", via: "text" }, 1);
  assert.deepEqual(await ask({ t: "wait", rid: r.rid }, page("doc-T1")), { done: true, ok: true, code: "4829", account: "", via: "text" });
  // An authenticator reply is still 6-8 digits, and carries no via.
  const r2 = await ask({ t: "ask", user: "w" }, page("doc-T2"));
  replyBlob = await phoneReply(r2.rid, { ok: true, code: "4829", account: "w" }, 2);
  assert.equal((await ask({ t: "wait", rid: r2.rid }, page("doc-T2"))).ok, false);
  const r3 = await ask({ t: "ask", user: "w" }, page("doc-T3"));
  replyBlob = await phoneReply(r3.rid, { ok: true, code: "287082", account: "w" }, 3);
  assert.deepEqual(await ask({ t: "wait", rid: r3.rid }, page("doc-T3")), { done: true, ok: true, code: "287082", account: "w" });
  // Not digits is refused either way.
  const r4 = await ask({ t: "ask", user: "w" }, page("doc-T4"));
  replyBlob = await phoneReply(r4.rid, { ok: true, code: "48a9", via: "text" }, 4);
  assert.equal((await ask({ t: "wait", rid: r4.rid }, page("doc-T4"))).ok, false);
});

test("asking again on the same page reuses a fresh request, and makes a new one once it expired", async () => {
  store.pairing = pairing();
  const r = await ask({ t: "ask", user: "w" }, page("doc-E"));
  assert.equal((await ask({ t: "ask", user: "w" }, page("doc-E"))).rid, r.rid);
  // 61 s on (the listener may be another module instance's, so the clock moves, not its map).
  const real = Date.now;
  Date.now = () => real() + 61000;
  let again;
  try { again = await ask({ t: "ask", user: "w" }, page("doc-E")); } finally { Date.now = real; }
  assert.ok(again.ok);
  assert.notEqual(again.rid, r.rid);
});

test("the phone's state: not paired, reachable within 30 minutes of the relay seeing it, else asleep", () => {
  assert.deepEqual(phoneState(false, { now: 100, phone_seen: 100 }), { state: "unpaired", ago: null });
  assert.deepEqual(phoneState(true, { now: 1000, phone_seen: 940 }), { state: "reachable", ago: 60 });
  assert.deepEqual(phoneState(true, { now: 10000, phone_seen: 10000 - 30 * 60 - 60 }), { state: "asleep", ago: 30 * 60 + 60 });
  assert.deepEqual(phoneState(true, { now: 1000, phone_seen: null }), { state: "asleep", ago: null });   // not seen since the relay started
  assert.deepEqual(phoneState(true, null), { state: "asleep", ago: null });                            // the relay didn't answer
});

test("the icon's tooltip shows the pairing and the phone, from the relay's status call", async () => {
  delete store.pairing;
  const before = calls.length;
  await _test.phoneStatus(true);
  assert.match(badge.title, /not paired/);
  assert.equal(calls.length, before);                                      // not paired: no relay call
  store.pairing = pairing();
  const now = Math.floor(Date.now() / 1000);
  relayStatus = { paired: true, phone_seen: now - 120, now };
  await _test.phoneStatus(true);
  assert.match(badge.title, /reachable; seen 2 minutes ago/);
  assert.ok(calls.some(([u, m]) => u.endsWith("/v1/status") && m === "GET"));
  relayStatus = { paired: true, phone_seen: now - 3 * 3600, now };
  await _test.phoneStatus(true);
  assert.match(badge.title, /asleep or offline.*seen 3 hours ago/);
  relayStatus = null;                                                      // the relay is down
  await _test.phoneStatus(true);
  assert.match(badge.title, /asleep or offline/);
  // Within 20 s a page load reuses the last answer instead of spending a relay call.
  relayStatus = { paired: true, phone_seen: now, now };
  await _test.phoneStatus(true);
  const n = calls.length;
  await _test.phoneStatus();
  assert.equal(calls.length, n);
  // The options page gets the same state.
  assert.deepEqual((await _test.options({ t: "status" })).phone, { state: "reachable", ago: 0 });
});

test("the icon's dot: red unpaired or unreachable, blinking while the phone asks, green on a saved site or a fill", () => {
  const d = (o) => dotState({ paired: true, reachable: true, siteSaved: false, pending: false, filled: false, ...o }).dot;
  assert.equal(d({ paired: false, pending: true, siteSaved: true }), "red");
  assert.equal(d({ reachable: false }), "red");
  assert.equal(d({ reachable: false, siteSaved: true }), "red");
  assert.equal(d({ pending: true }), "blink");
  assert.equal(d({ pending: true, reachable: false }), "blink");        // a request wakes a sleeping phone: it shows waiting
  assert.equal(d({ siteSaved: true }), "green");
  assert.equal(d({ filled: true, reachable: false }), "green");         // a code just went in
  assert.equal(d({}), "none");
  assert.match(dotState({ paired: true, reachable: true, pending: true }).words, /fingerprint/);
});

// The listener is the second module instance's (imported again above): its state is the one the messages reach.
const again = () => import("../background.js?again");
// A tab of its own, with nothing left waiting from the tests above.
const own = (doc) => { store.domains = { list: ["github.com"], groups: [["github.com"]], at: 1 }; return tab("https://github.com/login", 21, "https://github.com/login", doc); };

test("a tab's tooltip follows its own state: saved site, waiting on the phone, then the code in", async () => {
  store.pairing = pairing();
  const now = Math.floor(Date.now() / 1000);
  relayStatus = { paired: true, phone_seen: now, now };
  await (await again())._test.phoneStatus(true);
  await ask({ t: "eligible" }, own("doc-D1"));
  assert.match(badge.tabs[21], /saved on the phone/);
  const r = await ask({ t: "ask", user: "w" }, own("doc-D1"));
  assert.match(badge.tabs[21], /waiting for your fingerprint/);
  replyBlob = await phoneReply(r.rid, { ok: true, code: "287082", account: "w" }, 90);
  assert.equal((await ask({ t: "wait", rid: r.rid }, own("doc-D1"))).ok, true);
  assert.match(badge.tabs[21], /the code went in/);
  (await again())._test.tabs.delete(21);
});

test("a password going in sends code.ready once per page with the tab's site; its answer carries no code", async () => {
  store.pairing = pairing();
  const from = calls.length;
  replyBlob = (rid) => phoneReply(rid, { ok: true, for: 30 }, 1, "code.ready.reply");
  assert.deepEqual(await ask({ t: "ready", user: "w", host: "evil.io" }, own("doc-R1")), { ok: true });
  const post = calls.slice(from).find(([u, m]) => u.endsWith("/v1/requests") && m === "POST");
  const { blob } = JSON.parse(new TextDecoder().decode(post[2]));
  const o = await open(store.pairing.l2p, store.pairing.pid, "q", blob, 0, Date.now());
  const env = JSON.parse(new TextDecoder().decode(o.plain));
  assert.equal(env.kind, "code.ready");
  assert.deepEqual(env.body, { host: "github.com", frame: "github.com", user: "w" });   // the host in the message is ignored
  assert.deepEqual(await ask({ t: "ready" }, own("doc-R1")), { ok: false, why: "asked" });
  // Denied on the phone: nothing changes, the code field asks as before.
  replyBlob = (rid) => phoneReply(rid, { ok: false, why: "denied" }, 2, "code.ready.reply");
  assert.deepEqual(await ask({ t: "ready" }, own("doc-R2")), { ok: false, why: "denied" });
  // A code.reply (with a code) is never taken as the pre-approval's answer.
  replyBlob = (rid) => phoneReply(rid, { ok: true, code: "287082" }, 3);
  assert.equal((await ask({ t: "ready" }, own("doc-R3"))).ok, false);
  const before = calls.length;
  assert.equal((await ask({ t: "ready" }, tab("https://evil.io/"))).ok, false);
  assert.equal(calls.length, before);
  assert.equal((await again())._test.tabs.get(21)?.rids.size ?? 0, 0);                   // nothing left blinking
});

// owner, 2026-10-26: the codes his fingerprint sent ahead fill the field with no trip to the phone, for 30 s at most.
test("held codes: only well-formed ones, cut at 30 s, used only on the same site and inside their time", () => {
  const now = 1_000_000_040_000;
  const h = heldCodes({ account: "GitHub", codes: [
    { code: "111111", from: 1_000_000_020, until: 1_000_000_050 },
    { code: "222222", from: 1_000_000_050, until: 1_000_000_999 },
    { code: "12ab56", from: 1_000_000_050, until: 1_000_000_080 } ] }, now);
  assert.deepEqual(h.codes.map((c) => c.code), ["111111", "222222"]);
  assert.equal(h.codes[1].until, 1_000_000_070);                                   // never past the 30 s
  const at = { ...h, site: "github.com" };
  assert.equal(heldNow(at, "github.com", now)?.code, "111111");
  assert.equal(heldNow(at, "github.com", 1_000_000_055_000)?.code, "222222");
  assert.equal(heldNow(at, "gitlab.com", now), null);                               // another site
  assert.equal(heldNow(at, "github.com", 1_000_000_069_500), null);                 // the last second: ask the phone
  assert.equal(heldCodes({ ok: true }, now), null);
});

test("the relay must be an https origin, and its token rides in the QR only when set", async () => {
  delete store.pairing;
  for (const relay of ["http://relay.example.com", "https://relay.example.com/v1", "https://u:p@relay.example.com", "relay.example.com", "", "https://relay.example.com/?x=1"])
    assert.equal((await _test.options({ t: "offer", name: "L", relay })).ok, false, relay);
  assert.equal((await _test.options({ t: "offer", name: "L", relay: RELAY, token: "bad token!" })).ok, false);
  const withToken = await _test.options({ t: "offer", name: "L", relay: "https://Relay.Example.com/", token: "tok_123" });
  assert.match(withToken.qr, /&r=https:\/\/relay\.example\.com&n=L&t=tok_123$/);
  assert.equal((await _test.options({ t: "status" })).relay, RELAY);
  // While pairing, the offer's relay grant is kept too.
  granted = [RELAY_PERM, "https://github.com/*"];
  removed.length = 0;
  await _test.register();
  assert.ok(!removed.includes(RELAY_PERM));
  store.offer = undefined;
});

// Review 2026-10-27: a held code is this pairing's and this account's only, and goes with an unpair.
test("held codes are bound to the pairing and the account, and an unpair drops them", async () => {
  const now = 1_000_000_040_000;
  const h = { ...heldCodes({ account: "w", codes: [{ code: "111111", from: 1_000_000_020, until: 1_000_000_050 }] }, now), site: "github.com", pid: "P".repeat(22), user: "w" };
  assert.equal(heldFor(h, "github.com", "P".repeat(22), "w", now)?.code, "111111");
  assert.equal(heldFor(h, "github.com", "P".repeat(22), "", now)?.code, "111111");      // the page names no one: the held account
  // Codex's reproduction: approved with an empty hint (the phone picked Alice), then the code page names Bob.
  const blind = { ...h, user: "" };
  assert.equal(heldFor(blind, "github.com", "P".repeat(22), "bob", now), null);
  assert.equal(heldFor(blind, "github.com", "P".repeat(22), "", now)?.code, "111111");
  // The phone said the site has only that account: a name the page shows later can't mean another, so no second ask.
  const only = { ...heldCodes({ account: "w", only: true, codes: [{ code: "111111", from: 1_000_000_020, until: 1_000_000_050 }] }, now), site: "github.com", pid: "P".repeat(22), user: "" };
  assert.equal(heldFor(only, "github.com", "P".repeat(22), "bob", now)?.code, "111111");
  assert.equal(heldFor(only, "github.com", "Q".repeat(22), "bob", now), null);           // still this pairing's only
  assert.equal(heldFor(h, "github.com", "Q".repeat(22), "w", now), null);              // another pairing
  assert.equal(heldFor(h, "github.com", undefined, "w", now), null);                   // unpaired
  assert.equal(heldFor(h, "github.com", "P".repeat(22), "other", now), null);           // another account
  assert.equal(heldFor({ ...h, pid: undefined }, "github.com", "P".repeat(22), "w", now), null);
  _test.held.set(99, h);
  await _test.options({ t: "unpair" });
  assert.equal(_test.held.size, 0);
  store.pairing = pairing();
});

test("an authenticator code whose period ended on the way is never typed in", async () => {
  store.pairing = pairing();
  const r = await ask({ t: "ask", user: "w" }, page("doc-X1"));
  replyBlob = await phoneReply(r.rid, { ok: true, code: "287082", account: "w", ttl: 2, until: Math.floor(Date.now() / 1000) - 1 }, 1);
  assert.deepEqual(await ask({ t: "wait", rid: r.rid }, page("doc-X1")), { done: true, ok: false, why: "expired code" });
  const r2 = await ask({ t: "ask", user: "w" }, page("doc-X2"));
  replyBlob = await phoneReply(r2.rid, { ok: true, code: "287082", account: "w", ttl: 20, until: Math.floor(Date.now() / 1000) + 20 }, 2);
  assert.deepEqual(await ask({ t: "wait", rid: r2.rid }, page("doc-X2")), { done: true, ok: true, code: "287082", account: "w" });
});

test("a pairing offer lives 10 minutes, then its QR is gone and its hello is refused", async () => {
  assert.equal(offerFresh({ at: 1000 }, 1000 + 9 * 60000), true);
  assert.equal(offerFresh({ at: 1000 }, 1000 + 10 * 60000), false);
  assert.equal(offerFresh({}, 1000), false);
  delete store.pairing;
  await _test.options({ t: "offer", name: "L", relay: RELAY });
  assert.equal((await _test.options({ t: "status" })).pending, true);
  hello = await phoneHello();
  store.offer.at -= 11 * 60000;
  const s = await _test.options({ t: "status" });
  assert.equal(s.pending, false);
  assert.equal(s.qr, undefined);
  assert.equal(store.offer, undefined);
  assert.equal((await _test.options({ t: "hello" })).paired, false);
  assert.equal(store.pairing, undefined);
  store.pairing = pairing();
});

// Codex's reproduction (review 2026-10-27): two replies that cross on the way; the later counter arrives first.
test("replies that arrive out of order are both taken, each once", async () => {
  store.pairing = pairing();
  const r1 = await ask({ t: "ask", user: "w" }, page("doc-O1"));
  const r2 = await ask({ t: "ask", user: "w" }, page("doc-O2"));
  const until = Math.floor(Date.now() / 1000) + 20;
  const b1 = await phoneReply(r1.rid, { ok: true, code: "111111", account: "w", ttl: 20, until }, 1);
  const b2 = await phoneReply(r2.rid, { ok: true, code: "222222", account: "w", ttl: 20, until }, 2);
  replyBlob = b2;
  assert.equal((await ask({ t: "wait", rid: r2.rid }, page("doc-O2"))).code, "222222");
  replyBlob = b1;
  assert.equal((await ask({ t: "wait", rid: r1.rid }, page("doc-O1"))).code, "111111");
  assert.equal(store.pairing.recv, 2);
  // The same counter again is a replay.
  const r3 = await ask({ t: "ask", user: "w" }, page("doc-O3"));
  replyBlob = await phoneReply(r3.rid, { ok: true, code: "333333", account: "w", ttl: 20, until }, 1);
  assert.equal((await ask({ t: "wait", rid: r3.rid }, page("doc-O3"))).ok, false);
  // The window: gaps below the highest, only WINDOW back; a pairing saved before (no gaps) stays strict.
  assert.deepEqual(windowAfter(5, 2), { recv: 5, gaps: [3, 4] });
  assert.deepEqual(windowAfter(3, 5, [3, 4]), { recv: 5, gaps: [4] });
  assert.equal(windowFresh(3, 5, [4]), false);
  assert.equal(windowFresh(1, 2), false);
  assert.equal(windowAfter(100, 2).gaps.length, 31);
});

// 2026-10-27: the timing trace and the keepalive, after a night of 20-80 s waits nobody could place.
test("the trace shows every hop by its shape: never a code, an account, a laptop name or a user name", async () => {
  store.pairing = { ...pairing(), name: "the owners laptop" };
  const r = await ask({ t: "ask", user: "alice@example.com", seen: Date.now() - 1234 }, page("doc-TR1"));
  replyBlob = await phoneReply(r.rid, { ok: true, code: "918273", account: "alice@example.com" }, 50);
  assert.equal((await ask({ t: "wait", rid: r.rid }, page("doc-TR1"))).code, "918273");
  await ask({ t: "remember", user: "alice@example.com" }, page("doc-TR1"));
  assert.equal((await ask({ t: "status" }, optionsPage)).name, "the owners laptop");
  const lines = (await again())._test.trace().map((e) => e.line).join("\n");
  assert.match(lines, /send posted code.request/);
  assert.match(lines, /answer wait \{"ok":true,"done":true,"code":"6 digits","account":"named"\}/);
  assert.match(lines, /worker start/);
  assert.match(lines, /field seen 12\d\d ms before this ask/);
  for (const secret of ["918273", "alice", "the owners", store.pairing.l2p, store.pairing.p2l]) assert.doesNotMatch(lines, new RegExp(secret));
  assert.equal(shape({ ok: true, qr: "sphinx:1?...", rid: "ABCDEFGHIJKLMNOPQRSTUV", items: [1, 2] }), '{"ok":true,"rid":"ABCDEF","items":2}');
  const t = await ask({ t: "trace" }, optionsPage);
  assert.ok(t.lines.length > 0 && t.lines.every((e) => typeof e.at === "number" && typeof e.line === "string"));
  assert.equal((await ask({ t: "trace" }, page("doc-TR1"))).ok, false);    // the options page's only
  await ask({ t: "traceClear" }, optionsPage);
  assert.ok((await ask({ t: "trace" }, optionsPage)).lines.length <= 2);   // the clear and this ask
});

test("a relay call in flight keeps the worker alive: an extension API call every 20 s until it returns", async () => {
  store.pairing = pairing();
  let pings = 0;
  chrome.runtime.getPlatformInfo = async () => { pings++; };
  mock.timers.enable({ apis: ["setInterval"] });
  try {
    let go;
    fetchGate = new Promise((r) => { go = r; });
    relayStatus = { paired: true, phone_seen: 1, now: 1 };
    const inflight = _test.phoneStatus(true);
    while (!calls.at(-1)?.[0].endsWith("/v1/status")) await new Promise((r) => setTimeout(r, 5));   // the fetch is now waiting on the gate
    mock.timers.tick(KEEPALIVE_MS);
    mock.timers.tick(KEEPALIVE_MS);
    assert.equal(pings, 2);
    go(); fetchGate = null;
    await inflight;
    mock.timers.tick(KEEPALIVE_MS);
    assert.equal(pings, 2);                                 // nothing in flight: no more
  } finally { mock.timers.reset(); delete chrome.runtime.getPlatformInfo; }
});
