// Sphinx: the service worker. It holds the pairing (derived keys only; the X25519 private key is dropped once the
// phone's hello is checked), talks to the relay with HMAC-signed requests, and answers the content script. A code is
// asked for only when the tab's host and the frame's host (from Chrome, never the page) are both sites of ONE saved
// account, and the content script runs only on the exact sites he granted (registered here, top frame only). The
// phone checks the same again. Nothing here ever submits a form.
//
// Every message to or from the phone is one typed, sealed envelope: {v: 1, kind, rid, body} (docs/DESIGN.md). Kinds now:
// code.request / code.reply, code.ready / code.ready.reply and domains.request / domains.reply, on the one pairing that
// later kinds share. A code.reply may carry a code from an SMS or email (via "text"), sent with his fingerprint while
// this request waited. A code.ready (his password went in) asks his fingerprint early; its reply never carries a code.
import { b64u, finish, newOffer, open, openChunk, relayKey, seal, sealChunk, sha256Hex, signed, unb64u } from "./crypto.js";
import { CHUNK, MAX_FILE, chunksFor, httpUrl, item, label, safeName } from "./handoff.js";
import { allowed, matches, normalize, patterns, savable, setPsl } from "./domains.js";
import { relayOrigin } from "./relay.js";

const TTL = 60000;
// A pairing offer (its QR) lives 10 minutes from when it was made (review 2026-10-27: they never expired).
const OFFER_MS = 10 * 60 * 1000;
export const offerFresh = (o, now = Date.now()) => !!o && typeof o.at === "number" && now - o.at >= 0 && now - o.at < OFFER_MS;
/** The current offer, or null; an expired one is dropped on the way. */
async function currentOffer() {
  const o = await get("offer");
  if (o && !offerFresh(o)) { await locked(async () => { const now = await get("offer"); if (now && !offerFresh(now)) await drop("offer"); }); return null; }
  return o || null;
}
const RID = /^[A-Za-z0-9_-]{22}$/;
const TOKEN = /^[A-Za-z0-9_-]{1,128}$/;
const te = new TextEncoder(), td = new TextDecoder();

// The pairing keys, relay key and counters live in storage.local, which Chrome exposes to content scripts by default
// (AC6). It is closed to this extension's own pages and worker first, at every worker start (Chrome documents no
// persistence for the setting), and every storage call and content-script registration waits for that. If Chrome
// refuses or lacks it (Chrome 137 has no local.setAccessLevel; 146 and later do, hence minimum_chrome_version), everything
// that needs storage fails closed. The content script never touches storage itself.
const trusted = typeof chrome.storage.local.setAccessLevel === "function"
  ? chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" })
  : Promise.reject(new Error("this Chrome can't close storage to content scripts"));
trusted.catch(() => {});
const get = async (k) => { await trusted; return (await chrome.storage.local.get(k))[k]; };
const put = async (k, v) => { await trusted; return chrome.storage.local.set({ [k]: v }); };
const drop = async (k) => { await trusted; return chrome.storage.local.remove(k); };

let pslReady = null;
// A failed load isn't cached: the next call tries again.
const ready = () => (pslReady ??= fetch(chrome.runtime.getURL("public_suffix_list.dat")).then((r) => r.text()).then(setPsl).catch((e) => { pslReady = null; throw e; }));

/** Chrome keeps host permissions as `scheme://host/*` whatever path the manifest gave; compare in that form. */
export const canonical = (p) => p.replace(/^([a-z*]+:\/\/[^/]+)\/.*$/, "$1/*");

// The pairing's counters are read-modify-write: one change at a time, in order, so two sends or a send and a reply
// can never reuse a counter or roll one back.
let chain = Promise.resolve();
function locked(f) {
  const run = chain.then(f, f);
  chain = run.catch(() => {});
  return run;
}

// Chrome ends an idle extension worker after 30 s, and a relay long poll is 25 s plus the network. While any relay call
// is in flight an extension API is called every KEEPALIVE_MS, which resets that clock (Chrome 110 and later), so a wait
// on the phone never ends with the worker (2026-10-27: the relay saw this laptop stop polling for 11-82 s at a time).
export const KEEPALIVE_MS = 20000;
let inflight = 0, keep = null;
function hold() {
  if (++inflight !== 1) return;
  keep = setInterval(() => { try { chrome.runtime.getPlatformInfo?.()?.catch?.(() => {}); } catch { /* none */ } }, KEEPALIVE_MS);
  keep.unref?.();   // (node, in the tests)
}
function release() {
  if (--inflight !== 0) return;
  clearInterval(keep);
  keep = null;
}

// One call to the pairing's relay (p.relay, an https origin; its routes are /v1/...), HMAC-signed with its relay key.
async function relay(p, method, path, body) {
  const bytes = body ? te.encode(JSON.stringify(body)) : new Uint8Array();
  const url = new URL(`${p.relay}/v1${path}`);
  const headers = await signed(p, method, url.pathname, url.search.replace(/^\?/, ""), bytes);
  hold();
  let r;
  try {
    r = await fetch(url, { method, headers: { ...headers, ...(body ? { "content-type": "application/json" } : {}) }, body: body ? bytes : undefined, cache: "no-store", credentials: "omit", redirect: "error" });
  } finally { release(); }
  if (r.status === 204) return null;
  if (!r.ok) throw new Error(`relay ${r.status}`);
  return r.json();
}

const newRid = () => b64u(crypto.getRandomValues(new Uint8Array(16)));

// TIMING (2026-10-27): every hop with the time, in this worker's console and in a trace the options page shows. The trace
// lives in storage.session (this browser session only, closed to content scripts), so it outlives a worker restart and
// shows one ("worker start"). Never a code, a key, an account name, a laptop name or a user name: answers go in as
// their shape (`shape`), messages as their kind and the tab's host.
const TRACE_MAX = 300;
let trace = [], traceFlush = null;
const traceReady = (async () => { try { trace = ((await chrome.storage.session.get("trace")).trace || []).slice(-TRACE_MAX); } catch { trace = []; } })();
export const T = (...a) => {
  const line = a.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(" ");
  console.log(`SPHINX ${new Date().toISOString().slice(11, 23)}`, line);
  traceReady.then(() => {
    trace.push({ at: Date.now(), line });
    if (trace.length > TRACE_MAX) trace.splice(0, trace.length - TRACE_MAX);
    clearTimeout(traceFlush);
    traceFlush = setTimeout(() => { chrome.storage.session.set({ trace }).catch(() => {}); }, 200);
    traceFlush.unref?.();
  });
};
/** An answer as the trace shows it: flags and counts only. A code, an account, a laptop name or a QR never goes in. */
export function shape(r) {
  if (!r || typeof r !== "object") return String(r);
  const out = {};
  for (const k of ["ok", "done", "why", "paired", "pending", "stale", "got", "state"]) if (k in r) out[k] = r[k];
  if ("rid" in r) out.rid = String(r.rid).slice(0, 6);
  if ("code" in r) out.code = `${String(r.code).length} digits`;
  if ("account" in r) out.account = r.account ? "named" : "";
  for (const k of ["items", "matches", "domains", "lines"]) if (Array.isArray(r[k])) out[k] = r[k].length;
  return JSON.stringify(out);
}
T("worker start");
const host = (url) => { try { return new URL(url).host; } catch { return ""; } };

// One envelope out, sealed with the next counter. The counter is taken and saved under the lock.
async function send(kind, body) {
  const rid = newRid();
  T("send start", kind, rid.slice(0, 6));
  const { p, blob } = await locked(async () => {
    const p = await get("pairing");
    if (!p) throw new Error("not paired");
    const ctr = p.sent + 1;
    await put("pairing", { ...p, sent: ctr });
    return { p, blob: await seal(p.l2p, p.pid, "q", ctr, Date.now() + TTL, te.encode(JSON.stringify({ v: 1, kind, rid, body }))) };
  });
  await relay(p, "POST", "/requests", { rid, blob });
  T("send posted", kind, rid.slice(0, 6));
  return { rid, pid: p.pid };
}

// The replay window (review 2026-10-27): a sealed counter is taken if it is above the highest seen, or one of the
// counters skipped below it (`gaps`, at most WINDOW back) not yet seen. Two replies that cross on the way (or two
// requests posted out of order) both arrive; each is still taken once. Pairings saved before have no gaps: strict.
export const WINDOW = 32;
export function windowFresh(ctr, recv, gaps = []) { return ctr > recv || gaps.includes(ctr); }
export function windowAfter(ctr, recv, gaps = []) {
  if (ctr <= recv) return { recv, gaps: gaps.filter((g) => g !== ctr) };
  const skipped = [];
  for (let g = Math.max(recv + 1, ctr - WINDOW + 1); g < ctr; g++) skipped.push(g);
  return { recv: ctr, gaps: [...gaps, ...skipped].filter((g) => g > ctr - WINDOW) };
}

// One long poll (at most 25 s on the relay's side) for the envelope answering `rid`; null while there is none yet.
async function receive(rid) {
  T("poll reply", rid.slice(0, 6));
  const p = await get("pairing");
  if (!p) throw new Error("not paired");
  const r = await relay(p, "GET", `/replies/${rid}`);
  if (!r || typeof r.blob !== "string") return null;
  return locked(async () => {
    const now = await get("pairing");
    if (!now || now.pid !== p.pid) throw new Error("not paired");
    const o = await open(now.p2l, now.pid, "r", r.blob, Math.max(0, now.recv - WINDOW), Date.now());
    if (!o.ok) throw new Error(`reply refused (${o.why})`);
    if (!windowFresh(o.ctr, now.recv, now.gaps || [])) throw new Error("reply refused (replay)");
    let env;
    try { env = JSON.parse(td.decode(o.plain)); } catch { throw new Error("reply unreadable"); }
    if (!env || env.v !== 1 || env.rid !== rid || typeof env.kind !== "string" || typeof env.body !== "object" || env.body === null) throw new Error("reply for another request");
    await put("pairing", { ...now, ...windowAfter(o.ctr, now.recv, now.gaps || []) });
    return env;
  });
}

// ---- the phone's state: not paired, reachable, asleep (the owner, 2026-10-25); the icon's dot shows it ----

// What the icon calls "reachable": the phone reached the gateway in the last 30 minutes (it checks in about every 15,
// its heartbeat). Only what the icon says; asking is never held back by it, a sleeping phone still wakes on a request.
const FRESH_S = 30 * 60;
// One status call at most every 20 s: it spends the pairing's 60 authenticated calls a minute on the relay.
const STATUS_EVERY = 20000;

/** "unpaired", "reachable" or "asleep" (asleep, offline, or the relay didn't answer), and how long since the phone was seen. */
export function phoneState(paired, s) {
  if (!paired) return { state: "unpaired", ago: null };
  if (!s || typeof s.now !== "number" || typeof s.phone_seen !== "number") return { state: "asleep", ago: null };
  const ago = Math.max(0, s.now - s.phone_seen);
  return { state: ago <= FRESH_S ? "reachable" : "asleep", ago };
}

const BADGE = {
  unpaired: { title: "Sphinx: not paired. Open the options to pair." },
  reachable: { title: "Sphinx: paired, the phone is reachable" },
  asleep: { title: "Sphinx: paired, the phone is asleep or offline (a request still wakes it)" },
};
const mins = (s) => (s < 90 ? "a minute" : s < 5400 ? `${Math.round(s / 60)} minutes` : `${Math.round(s / 3600)} hours`);

let status = null;   // {state, ago, at}: the last answer, so a page load doesn't ask the relay again within STATUS_EVERY
async function phoneStatus(force = false) {
  if (!force && status && Date.now() - status.at < STATUS_EVERY) return status;
  const p = await get("pairing");
  let s = null;
  if (p) { try { s = await relay(p, "GET", "/status"); } catch { s = null; } }
  status = { ...phoneState(!!p, s), at: Date.now() };
  await paintAll();
  return status;
}

// ---- the toolbar icon's dot, per tab (owner, 2026-10-26: "a green dot or red dot and a blinking dot") ----

/**
 * The dot on the icon and the words in its tooltip. Red: not paired, or the phone isn't reachable. White, blinking: a
 * request (a code, or a pre-approval) waits on the phone. Green: this tab's site is saved on the phone, or a code just
 * went in (jade). Grey ("none"): paired, the phone reachable, a site that isn't saved.
 */
export function dotState({ paired, reachable, siteSaved, pending, filled }) {
  if (!paired) return { dot: "red", words: BADGE.unpaired.title };
  if (pending) return { dot: "blink", words: "Sphinx: waiting for your fingerprint on the phone" };
  if (filled) return { dot: "green", words: "Sphinx: the code went in" };
  if (!reachable) return { dot: "red", words: BADGE.asleep.title };
  if (siteSaved) return { dot: "green", words: "Sphinx: this site is saved on the phone" };
  return { dot: "none", words: BADGE.reachable.title };
}
// Strong colours: they fill the icon's background, so they have to read on any toolbar (the owner, 2026-10-26). The
// basalt-and-jade palette: jade = saved site, white = the phone is asking, red = not reachable.
const DOT = { red: "#f05a45", green: "#7fd6aa", blink: "#f2f2f2", none: "#7d8590" };

const tabs = new Map();   // tab id -> {siteSaved, filled, rids: Map(rid -> until)}: in memory, gone with the worker
const tabOf = (id) => { if (!tabs.has(id)) tabs.set(id, { siteSaved: false, filled: false, rids: new Map() }); return tabs.get(id); };
const live = (t) => !!t && [...t.rids.values()].some((until) => until > Date.now());

/** A request this tab sent waits on the phone until [until] (or [settle] ends it): the dot blinks meanwhile. */
function waitingOn(tabId, rid, until) { tabOf(tabId).rids.set(rid, until); paint(tabId); blink(); }
function settle(tabId, rid, filled = false) {
  const t = tabs.get(tabId);
  if (!t) return;
  t.rids.delete(rid);
  if (filled) t.filled = true;
  paint(tabId);
}

let blinkOn = true, blinking = null;
/** One setTimeout chain while some tab waits (it never keeps the worker up on its own: a waiting request's fetch does). */
function blink() {
  if (blinking) return;
  const step = () => {
    const ids = [...tabs].filter(([, t]) => live(t)).map(([id]) => id);
    if (!ids.length) { blinking = null; blinkOn = true; return; }
    blinkOn = !blinkOn;
    ids.forEach(paint);
    blinking = setTimeout(step, 500);
    blinking.unref?.();   // (node, in the tests)
  };
  blinking = setTimeout(step, 500);
  blinking.unref?.();
}

let base = null;
const icons = () => (base ??= Promise.all([16, 32].map(async (n) =>
  [n, await createImageBitmap(await (await fetch(chrome.runtime.getURL(`icons/icon${n}.png`))).blob())])).catch((e) => { base = null; throw e; }));

/**
 * The icon in [color] (null: the plain coin), as setIcon's imageData. The state is the icon's own background: a full
 * bright disc with the coin set inside it, so it reads at 16 px (owner, 2026-10-26: a small dot was "literally
 * invisible").
 */
async function drawn(color) {
  const out = {};
  for (const [n, bmp] of await icons()) {
    const c = new OffscreenCanvas(n, n), g = c.getContext("2d");
    if (color) {
      g.beginPath(); g.arc(n / 2, n / 2, n / 2, 0, Math.PI * 2); g.fillStyle = color; g.fill();
      const inset = Math.max(2, Math.round(n * 0.16));
      g.drawImage(bmp, inset, inset, n - 2 * inset, n - 2 * inset);
    } else {
      g.drawImage(bmp, 0, 0, n, n);
    }
    out[n] = g.getImageData(0, 0, n, n);
  }
  return out;
}

/** One tab's icon and tooltip (no tab: the default every other tab shows). */
async function paint(tabId) {
  const t = tabId === undefined ? undefined : tabs.get(tabId);
  const st = status?.state ?? "asleep";
  const d = dotState({ paired: st !== "unpaired", reachable: st === "reachable", siteSaved: !!t?.siteSaved, pending: live(t), filled: !!t?.filled });
  const words = d.dot === "red" && st === "asleep" && status?.ago != null ? `${d.words}; seen ${mins(status.ago)} ago`
    : d.dot === "none" && status?.ago != null ? `${d.words}; seen ${mins(status.ago)} ago` : d.words;
  const color = d.dot === "blink" ? (blinkOn ? DOT.blink : null) : DOT[d.dot] || null;
  const at = tabId === undefined ? {} : { tabId };
  try {
    await chrome.action.setTitle({ title: words, ...at });
    await chrome.action.setIcon({ imageData: await drawn(color), ...at });
  } catch { /* no icon drawing (tests, a closed tab, Chrome closing): the tooltip and options page still say it */ }
  return d;
}
const paintAll = () => Promise.all([paint(undefined), ...[...tabs.keys()].map(paint)]);

// ---- the sites: the phone's list (per account), his grants, and where the content script runs ----

async function refreshDomains() {
  await ready();
  const { rid } = await send("domains.request", {});
  for (let i = 0; i < 3; i++) {
    const env = await receive(rid);
    if (!env) continue;
    if (env.kind !== "domains.reply" || !env.body.ok || !Array.isArray(env.body.groups)) throw new Error("the phone refused");
    const clean = (l) => [...new Set((Array.isArray(l) ? l : []).filter((d) => typeof d === "string").map(savable).filter(Boolean))];
    const groups = env.body.groups.map(clean).filter((g) => g.length).slice(0, 60);
    const list = [...new Set(groups.flat())];
    await put("domains", { list, groups, at: Date.now() });
    await register();
    return { ok: true, domains: list };
  }
  throw new Error("the phone didn't answer");
}

/** The relay's own permission (the pairing's, or the offer's while pairing): never dropped as a stale site grant. */
async function relayPerms() {
  const p = await get("pairing"), o = await currentOffer();
  return [p?.relay, o?.relay].filter(Boolean).map((r) => canonical(`${r}/*`));
}

/**
 * The content script runs on the exact saved sites he granted, top frame only, nowhere else. Grants for sites no
 * longer saved are dropped; the relay's permission and the manifest's own are never touched.
 * Registered for this browser session only, after storage is closed: after a restart none runs until this worker has
 * closed storage again (onStartup), so no page ever loads it while storage is still open to it.
 */
async function register() {
  await trusted;
  await ready();
  const list = (await get("domains"))?.list || [];
  const wanted = new Set(list.flatMap(patterns));
  const required = new Set([...(chrome.runtime.getManifest().host_permissions || []).map(canonical), ...(await relayPerms())]);
  const granted = (await chrome.permissions.getAll()).origins || [];
  const stale = granted.filter((o) => !wanted.has(o) && !required.has(o));
  if (stale.length) await chrome.permissions.remove({ origins: stale });
  const matches = granted.filter((o) => wanted.has(o) && !required.has(o));
  await chrome.scripting.unregisterContentScripts({ ids: ["codes"] }).catch(() => {});
  if (matches.length) {
    await chrome.scripting.registerContentScripts([{ id: "codes", js: ["detect.js", "content.js"], matches, allFrames: false, runAt: "document_end", persistAcrossSessions: false }]);
  }
  return matches;
}

/** The tab's and the frame's hosts (https only), from Chrome, when one saved account covers both; else null. */
async function eligible(sender) {
  if (!(await get("pairing"))) return null;
  await ready();
  let top, frame;
  try { top = new URL(sender.tab.url); frame = new URL(sender.url); } catch { return null; }
  if (top.protocol !== "https:" || frame.protocol !== "https:") return null;
  const t = normalize(top.hostname), f = normalize(frame.hostname);
  return t && f && allowed(t, f, (await get("domains"))?.groups) ? { host: t, frame: f, origin: top.origin, frameOrigin: frame.origin } : null;
}

// ---- messages: content scripts (from a tab) and the options page (an extension page), each its own small set ----

// One question per document: a request is bound to the pairing, both origins, the frame and the document that asked.
const waiting = new Map();   // "tab:frame:document" -> {rid, pid, origin, frameOrigin}
// The options page opens in a tab of its own (options_page), so a tab doesn't tell it from a content script: its origin
// does. Chrome sets sender.origin from the document, so no web page can claim this extension's origin.
const SELF = chrome.runtime.getURL("").replace(/\/$/, "");   // "chrome-extension://<id>", as Chrome writes sender.origin
const fromOptions = (s) => s.origin === SELF && s.url === chrome.runtime.getURL("options.html");
// The toolbar popup (or the same page opened in a tab from a notification).
const fromPopup = (s) => s.origin === SELF && s.url === chrome.runtime.getURL("popup.html");
const fromContent = (s) => !!s.tab && typeof s.tab.id === "number" && typeof s.url === "string" && typeof s.documentId === "string" && typeof s.frameId === "number"
  && s.origin !== SELF && !s.url.startsWith(SELF + "/");
const keyOf = (s) => `${s.tab.id}:${s.frameId}:${s.documentId}`;

/** The request this very document made, still on the same pairing and origins, or null. */
async function bound(s, rid) {
  const w = waiting.get(keyOf(s));
  if (!w || w.rid !== rid) return null;
  const e = await eligible(s), p = await get("pairing");
  if (!e || !p || p.pid !== w.pid || e.origin !== w.origin || e.frameOrigin !== w.frameOrigin) { waiting.delete(keyOf(s)); return null; }
  return w;
}

// The user name he typed, kept for the saved site that covers the page (not the page's own origin): AWS asks for it on
// signin.aws.amazon.com and for the code on us-east-1.signin.aws.amazon.com (the owner, 2026-10-23). Browser session only.
async function siteKey(host) {
  const groups = (await get("domains"))?.groups || [];
  return [...new Set(groups.flat().filter((d) => matches(host, d)))].sort().join("|");
}

// The documents that already sent a code.ready: one per page, whatever the content script asks.
const readied = new Set();

// The codes his fingerprint on a code.ready sent ahead, per tab: {site, account, codes: [{code, from, until}]}, in memory
// only (gone with the worker), for the window's 60 s at most (30 until 2026-10-27), and used once (owner, 2026-10-26: "hold it", "hold only
// for 30 seconds"). The code field of the same site in the same tab fills from them with no trip to the phone.
const held = new Map();
export function heldCodes(body, now = Date.now()) {
  if (!Array.isArray(body?.codes)) return null;
  const end = Math.floor(now / 1000) + 60;
  const codes = body.codes.filter((c) => c && typeof c.code === "string" && /^\d{6,8}$/.test(c.code) && Number.isInteger(c.from) && Number.isInteger(c.until) && c.until > c.from)
    // Up to 8: a 60 s window touches 5 periods of 15 s, 7 of 10 (Codex, 2026-10-27: a cap of 4 dropped the fifth).
    .map((c) => ({ code: c.code, from: c.from, until: Math.min(c.until, end) })).slice(0, 8);
  return codes.length ? { account: typeof body.account === "string" ? body.account.slice(0, 60) : "", only: body.only === true, codes } : null;
}
export function heldNow(h, site, now = Date.now()) {
  if (!h || h.site !== site) return null;
  const t = now / 1000;
  return h.codes.find((c) => c.from <= t && t < c.until - 1) || null;   // a second's margin: it still has to be typed and sent
}
/**
 * A held code for this ask only if it is the same pairing's and the same account's: another pairing, an unpair, or a
 * user name the code field's page names that the pre-approval didn't (a name that became known, or another one) never
 * gets it, and the phone is asked afresh (review 2026-10-27: the phone picked by the empty hint, the page named Bob).
 * Unless the phone said the site has only that one account: then no name can mean another (owner, 2026-10-27: the
 * second fingerprint on every sign-in was too slow).
 */
export function heldFor(h, site, pid, user, now = Date.now()) {
  if (!h || !pid || h.pid !== pid) return null;
  if (user && user !== h.user && !h.only) return null;
  return heldNow(h, site, now);
}

/** A code.reply for the document that asked, checked again at delivery: it may have navigated while the phone asked him. */
async function delivered(s, rid, env) {
  if (!(await bound(s, rid))) return { done: true, ok: false, why: "no such request" };
  waiting.delete(keyOf(s));
  if (env.kind !== "code.reply") return { done: true, ok: false, why: typeof env.body.why === "string" ? env.body.why.slice(0, 40) : "refused" };
  const b = env.body;
  // A code from an SMS or email he sent with his fingerprint (via "text") may be 4-8 digits and is never submitted;
  // an authenticator code is 6-8 (the owner, 2026-10-25).
  const text = b.via === "text";
  // An authenticator code whose period ended on the way (the reply may take up to a minute) is never typed in and sent
  // (review 2026-10-27): `until` is the unix second its period ends, with a second's margin to type it.
  if (!text && b.ok && Number.isInteger(b.until) && Date.now() / 1000 >= b.until - 1) return { done: true, ok: false, why: "expired code" };
  return b.ok && typeof b.code === "string" && (text ? /^\d{4,8}$/ : /^\d{6,8}$/).test(b.code)
    ? { done: true, ok: true, code: b.code, account: typeof b.account === "string" ? b.account.slice(0, 60) : "", ...(text ? { via: "text" } : {}) }
    : { done: true, ok: false, why: typeof b.why === "string" ? b.why.slice(0, 40) : "refused" };
}

async function content(m, s) {
  switch (m.t) {
    case "eligible": {
      const ok = !!(await eligible(s));
      // A page loaded here (its own dot: green when the site is saved); for a saved site the phone's state is brought up
      // to date too (at most every 20 s).
      tabOf(s.tab.id).siteSaved = ok;
      if (ok) phoneStatus().catch(() => {});
      paint(s.tab.id);
      return { ok };
    }
    case "ready": {
      // His password went in on a saved site (content.js, shouldReady): the phone asks him now, and his yes covers the code
      // the site asks for next, for 60 s, on the phone (code.ready, the owner 2026-10-26). The answer carries no code. The
      // site is the tab's (from Chrome), as for a code; once per document.
      const e = await eligible(s);
      if (!e) return { ok: false, why: "not a saved site" };
      if (readied.has(keyOf(s))) return { ok: false, why: "asked" };
      readied.add(keyOf(s));
      let user = typeof m.user === "string" ? m.user.slice(0, 120) : "";
      if (!user) user = ((await chrome.storage.session.get("hints")).hints || {})[await siteKey(e.host)]?.user || "";
      const { rid, pid } = await send("code.ready", { host: e.host, frame: e.frame, user });
      waitingOn(s.tab.id, rid, Date.now() + TTL);
      try {
        for (let i = 0; i < 3; i++) {
          const env = await receive(rid);
          if (!env) continue;
          const ok = env.kind === "code.ready.reply" && env.body.ok === true;
          if (ok) { const h = heldCodes(env.body); if (h) held.set(s.tab.id, { ...h, site: await siteKey(e.host), pid, user }); }
          return ok ? { ok: true } : { ok: false, why: typeof env.body.why === "string" ? env.body.why.slice(0, 40) : "refused" };
        }
        return { ok: false, why: "no answer" };
      } finally { settle(s.tab.id, rid); }
    }
    case "remember": {
      const e = await eligible(s);
      const user = typeof m.user === "string" ? m.user.trim().slice(0, 120) : "";
      if (!e || !user) return { ok: false };
      const key = await siteKey(e.host);
      if (!key) return { ok: false };
      const hints = (await chrome.storage.session.get("hints")).hints || {};
      hints[key] = { user, at: Date.now() };
      await chrome.storage.session.set({ hints });
      return { ok: true };
    }
    case "ask": {
      // The trace: how long the page script had the field before it asked (a number from the page, bounded).
      if (Number.isFinite(m.seen)) T("field seen", `${Math.max(0, Math.min(600000, Math.round(Date.now() - m.seen)))} ms before this ask`);
      const e = await eligible(s);
      if (!e) return { ok: false, why: "not a saved site" };
      let user = typeof m.user === "string" ? m.user.slice(0, 120) : "";
      if (!user) user = ((await chrome.storage.session.get("hints")).hints || {})[await siteKey(e.host)]?.user || "";
      // A code his fingerprint already sent (code.ready): straight in, once, nothing asked of the phone; only for this
      // pairing and this account.
      const h = held.get(s.tab.id), c = heldFor(h, await siteKey(e.host), (await get("pairing"))?.pid, user);
      if (h) held.delete(s.tab.id);
      if (c) { tabOf(s.tab.id).filled = true; paint(s.tab.id); return { ok: true, code: c.code, account: h.account }; }
      const old = waiting.get(keyOf(s));
      // The same document asking again gets its request back while it is fresh; once expired, a new one (he focused it later).
      if (old && old.exp > Date.now() && (await bound(s, old.rid))) return { ok: true, rid: old.rid };
      const { rid, pid } = await send("code.request", { host: e.host, frame: e.frame, user });
      const k = keyOf(s);
      waiting.set(k, { rid, pid, origin: e.origin, frameOrigin: e.frameOrigin, exp: Date.now() + TTL });
      setTimeout(() => waiting.get(k)?.rid === rid && waiting.delete(k), TTL + 15000);
      waitingOn(s.tab.id, rid, Date.now() + TTL);
      return { ok: true, rid };
    }
    case "wait": {
      // Only the rid this document was given, on the same origins and pairing: another tab, frame or a navigation gets nothing.
      if (typeof m.rid !== "string" || !RID.test(m.rid) || !(await bound(s, m.rid))) return { done: true, ok: false, why: "no such request" };
      const env = await receive(m.rid);
      if (!env) return { done: false };
      const r = await delivered(s, m.rid, env);
      settle(s.tab.id, m.rid, r.ok);
      return r;
    }
    default: return { ok: false, why: "unknown" };
  }
}

async function options(m) {
  switch (m.t) {
    case "status": {
      const p = await get("pairing"), o = await currentOffer(), d = await get("domains");
      const granted = (await chrome.permissions.getAll()).origins || [];
      const phone = await phoneStatus().catch(() => null);
      return { paired: !!p, name: p?.name, relay: p?.relay || o?.relay || (await get("relayUrl")) || "", pending: !!o && !p, qr: o?.qr, domains: d?.list || [], domainsAt: d?.at || 0, granted,
        phone: phone ? { state: phone.state, ago: phone.ago } : null };
    }
    case "offer": {
      const name = typeof m.name === "string" ? m.name.trim().slice(0, 40) : "";
      const relayUrl = relayOrigin(m.relay);
      if (!relayUrl) return { ok: false, why: "The relay must be an https address with no path, like https://relay.example.com" };
      const token = typeof m.token === "string" ? m.token.trim() : "";
      if (token && !TOKEN.test(token)) return { ok: false, why: "The relay token may only hold letters, digits, - and _" };
      const { offer, qr } = await newOffer(relayUrl, name || "Chrome laptop", token);
      // Each offer has its own generation; a hello for an older one (or after an unpair) is refused.
      await locked(async () => {
        await put("relayUrl", relayUrl);
        await put("offer", { ...offer, qr, gen: b64u(crypto.getRandomValues(new Uint8Array(12))), at: Date.now() });
      });
      return { ok: true, qr };
    }
    case "hello": {
      // Polled by the options page while the QR is up. 401 until the phone has registered the pairing.
      const o = await currentOffer();
      if (!o) return { paired: !!(await get("pairing")) };
      let h;
      try { h = await relay({ pid: o.pid, relay: o.relay, relayKey: b64u(await relayKey(o)) }, "GET", "/hello"); } catch { return { paired: false }; }
      if (typeof h?.hello !== "string") return { paired: false };
      const p = await finish(o, h.hello);
      // Consumed exactly once, and only if it is still the current offer: an unpair, a newer offer or another hello
      // that got here first all win. A pairing already made from this offer is never overwritten (its counters stand).
      const took = await locked(async () => {
        const now = await get("offer"), cur = await get("pairing");
        if (!now || !offerFresh(now) || now.gen !== o.gen || now.pid !== o.pid || (cur && cur.pid === o.pid)) return false;
        await drop("offer");
        await put("pairing", { ...p, name: o.name, at: Date.now() });
        held.clear();
        return true;
      });
      if (!took) return { paired: !!(await get("pairing")), stale: true };
      try { await refreshDomains(); } catch { /* the options page shows "no sites yet" */ }
      phoneStatus(true).catch(() => {});
      await alarm();
      return { paired: true };
    }
    case "refresh": return refreshDomains();
    case "granted": return { ok: true, matches: await register() };
    case "trace": { await traceReady; return { ok: true, lines: trace.map((e) => ({ at: e.at, line: e.line })) }; }
    case "traceClear": { await traceReady; trace.length = 0; await chrome.storage.session.set({ trace: [] }).catch(() => {}); return { ok: true }; }
    case "unpair": {
      await locked(() => drop(["pairing", "offer", "domains"]));
      waiting.clear();
      // Codes held from the old pairing go with it.
      held.clear();
      readied.clear();
      await register();
      await phoneStatus(true).catch(() => {});
      await alarm();
      await setInbox([]).catch(() => {});
      return { ok: true };
    }
    default: return { ok: false, why: "unknown" };
  }
}

chrome.runtime.onMessage.addListener((m, sender, reply) => {
  // Only this extension's own scripts can reach here (no externally_connectable); still, each side gets its own set.
  if (sender.id !== chrome.runtime.id || !m || typeof m !== "object" || typeof m.t !== "string") return false;
  T("message", m.t, host(sender.tab?.url));
  const run = fromOptions(sender) ? options(m) : fromPopup(sender) ? popup(m) : fromContent(sender) ? content(m, sender) : Promise.resolve({ ok: false, why: "unknown sender" });
  run.then((r) => { T("answer", m.t, shape(r)); reply(r); }, (e) => { T("error", m.t, String(e?.message || e)); reply({ ok: false, why: String(e?.message || e).slice(0, 80) }); });
  return true;
});

// The content script's registration lasts one browser session and was made only on install, startup and a sites
// refresh: one attempt that failed left every saved site silent until the next refresh (2026-10-27, after a reload).
// Now it is checked on every wake and before a page loads, and a failure is logged and tried again.
let healing = null;
export function heal(tries = 3) {
  return (healing ??= (async () => {
    if (typeof chrome.scripting?.getRegisteredContentScripts !== "function") return false;
    for (let i = 0; i < tries; i++) {
      try {
        if ((await chrome.scripting.getRegisteredContentScripts({ ids: ["codes"] })).length) return true;
        if (!(await get("pairing")) || !((await get("domains"))?.list || []).length) return false;
        await register();
        return true;
      } catch (e) {
        console.warn("Sphinx: content script not registered:", String(e?.message || e));
        await new Promise((r) => setTimeout(r, 2000 * (i + 1)));
      }
    }
    return false;
  })().finally(() => { healing = null; }));
}

chrome.runtime.onStartup.addListener(() => { currentOffer().catch(() => {}); heal(); phoneStatus(true).catch(() => {}); alarm(); });
chrome.runtime.onInstalled.addListener(() => { heal(); phoneStatus(true).catch(() => {}); alarm(); menus(); });   // an update replaces the old persistent registration
chrome.permissions.onRemoved.addListener(() => { register().catch((e) => console.warn("Sphinx: register failed:", String(e?.message || e))); });
heal();   // every wake of the worker
// A tab that loads a new page loses its green (a saved site's content script says so again), but keeps blinking while a
// request it sent still waits (a password form's submit navigates); a closed one is forgotten.
chrome.tabs?.onUpdated?.addListener((id, info, tab) => {
  if (info.status) T("tab", info.status, host(tab?.url));   // when the page started and finished loading, against the hops after it
  if (info.status === "loading") heal();
  const t = tabs.get(id);
  if (info.status === "loading" && t) { t.siteSaved = false; t.filled = false; paint(id); }
});
chrome.tabs?.onRemoved?.addListener((id) => { tabs.delete(id); });

// ---- handoff: links, text and small files between the phone and this laptop (docs/DESIGN.md, "Handoff") ----

const ALARM = "sphinx.outbox";

/** Laptop to phone: one sealed handoff.send on the pairing (a request like a code's; the phone gets it on its FCM wake). */
async function handoff(body) {
  const it = item(body);
  if (!it) return { ok: false, why: "not something Sphinx can send" };
  await send("handoff.send", it);
  return { ok: true };
}

/** A file to the phone: its chunks go up sealed under a fresh key first, then the handoff that carries the key. */
async function sendFile(name, mime, data) {
  if (!(data instanceof Uint8Array) || data.length < 1) return { ok: false, why: "empty file" };
  if (data.length > MAX_FILE) return { ok: false, why: `too big (at most ${MAX_FILE / 1024 / 1024} MB)` };
  const p = await get("pairing");
  if (!p) return { ok: false, why: "not paired" };
  const key = b64u(crypto.getRandomValues(new Uint8Array(32))), fid = b64u(crypto.getRandomValues(new Uint8Array(16)));
  const chunks = chunksFor(data.length);
  for (let n = 0; n < chunks; n++) {
    const blob = await sealChunk(key, fid, n, chunks, data.subarray(n * CHUNK, (n + 1) * CHUNK));
    await relay(p, "PUT", `/files/${fid}/${n}?of=${chunks}`, { blob });
  }
  return handoff({ type: "file", file: { fid, key, name: safeName(name), mime, size: data.length, chunks, sha256: await sha256Hex(data) } });
}

// What the phone sent, in storage.local (closed to content scripts, see `trusted`), newest first, kept until he removes
// it with × or Clear (owner, 2026-10-27: it used to go with the browser session, or after 10 minutes). At most INBOX_MAX;
// the oldest drop off. Each item: {id, at, type, url?, open?, text?, file?, saved?, gone?} (handoff.js `item`, plus a
// file's state once he downloaded it, or the relay no longer had it).
const INBOX_MAX = 200;
const inbox = async () => (await get("inbox")) || [];
async function setInbox(list) {
  const kept = list.slice(0, INBOX_MAX);
  await put("inbox", kept);
  try { await chrome.action.setBadgeText({ text: kept.length ? String(kept.length) : "" }); await chrome.action.setBadgeBackgroundColor({ color: "#7fd6aa" }); } catch { /* tests */ }
}
// Every change to the list goes through one chain of its own (Codex, 2026-10-27: a new item vanished when a mark
// overlapped a poll), not `locked`, which the code path's seals share (Fable: a slow list write must not hold a code).
let inboxChain = Promise.resolve();
function editInbox(f) {
  const run = inboxChain.then(async () => setInbox(f(await inbox())));
  inboxChain = run.catch(() => {});
  return run;
}
/** One item changed in place (a file's state), by id. */
const markInbox = (id, change) => editInbox((list) => list.map((x) => (x.id === id ? { ...x, ...change } : x)));

/**
 * Phone to laptop: the laptop's outbox on the relay, opened with the phone-push direction 'p' and its own counter
 * (pushRecv), so it never races the replies' counter. Each item is checked again here (`item`: http(s) links only,
 * text and file caps); it is listed and announced, never acted on. Everything fetched is acked, refused ones too.
 */
async function pollOutbox() {
  const p = await get("pairing");
  if (!p) return { ok: false, why: "not paired" };
  const r = await relay(p, "GET", "/outbox");
  const items = Array.isArray(r?.items) ? r.items : [];
  if (!items.length) return { ok: true, got: 0 };
  const got = [];
  await locked(async () => {
    let now = await get("pairing");
    if (!now || now.pid !== p.pid) return;
    for (const b of items) {
      if (typeof b?.blob !== "string" || typeof b?.rid !== "string") continue;
      const o = await open(now.p2l, now.pid, "p", b.blob, now.pushRecv || 0, Date.now());
      if (!o.ok) continue;
      now = { ...now, pushRecv: o.ctr };
      let env;
      try { env = JSON.parse(td.decode(o.plain)); } catch { continue; }
      if (!env || env.v !== 1 || env.kind !== "handoff.send" || env.rid !== b.rid) continue;
      const it = item(env.body);
      if (it) got.push({ id: env.rid, at: Date.now(), ...it });
    }
    await put("pairing", now);
  });
  await relay(p, "POST", "/outbox/ack", { rids: items.map((b) => b.rid).filter((x) => typeof x === "string") }).catch(() => {});
  if (got.length) {
    await editInbox((list) => [...got.reverse(), ...list]);
    for (const it of got) {
      try { chrome.notifications.create(`sphinx:${it.id}`, { type: "basic", iconUrl: "icons/icon128.png", title: "From your phone", message: `${label(it)}. Click to see it in Sphinx.` }); } catch { /* none */ }
    }
  }
  return { ok: true, got: got.length };
}

/**
 * A received file: its chunks down, opened, checked against the sealed size and sha256, then gone from the relay.
 * The relay keeps chunks about 10 minutes: a 404 or a missing chunk throws with `gone` set, so the item is kept and
 * labelled, not treated as a broken download.
 */
async function fetchFile(f) {
  const p = await get("pairing");
  if (!p) throw new Error("not paired");
  const out = new Uint8Array(f.size);
  for (let n = 0; n < f.chunks; n++) {
    let r;
    try { r = await relay(p, "GET", `/files/${f.fid}/${n}`); } catch (e) { if (/^relay 404$/.test(String(e?.message))) throw Object.assign(new Error("no longer on the relay"), { gone: true }); throw e; }
    if (!r || typeof r.blob !== "string") throw Object.assign(new Error("no longer on the relay"), { gone: true });
    const part = await openChunk(f.key, f.fid, n, f.chunks, r.blob);
    if (!part || n * CHUNK + part.length > f.size) throw new Error("the file didn't arrive whole");
    out.set(part, n * CHUNK);
  }
  if ((await sha256Hex(out)) !== f.sha256) throw new Error("the file doesn't match what the phone sent");
  // The relay's copy stays until the popup says the download started ("saved"): a popup closed in between, or a
  // download Chrome refused, would otherwise lose the file (Codex, 2026-10-27). The relay drops it after 10 min anyway.
  return out;
}

const b64std = (u8) => { let s = ""; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000)); return btoa(s); };
const fromB64std = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** The popup's messages (popup.html, this extension's own page): send, list, and act on one item at a click. */
async function popup(m) {
  switch (m.t) {
    case "inbox": {
      await pollOutbox().catch(() => {});
      return { ok: true, paired: !!(await get("pairing")), items: await inbox() };
    }
    case "dismiss": {
      await editInbox((list) => list.filter((x) => x.id !== m.id));
      return { ok: true };
    }
    case "clear": {
      // One section at a time: "texts" is texts and links, "files" the files.
      const files = m.section === "files";
      if (!files && m.section !== "texts") return { ok: false, why: "unknown section" };
      await editInbox((list) => list.filter((x) => (x.type === "file") !== files));
      return { ok: true };
    }
    case "openLink": {
      // His click on Open in the popup: only then does a tab open, and only for an http(s) link. The item stays listed.
      const it = (await inbox()).find((x) => x.id === m.id && x.type === "link");
      const url = it && httpUrl(it.url);
      if (!url) return { ok: false, why: "no such link" };
      await chrome.tabs.create({ url });
      return { ok: true };
    }
    case "file": {
      const it = (await inbox()).find((x) => x.id === m.id && x.type === "file");
      if (!it) return { ok: false, why: "no such file" };
      if (it.gone) return { ok: false, why: "no longer on the relay", gone: true };
      let data;
      try { data = await fetchFile(it.file); } catch (e) {
        if (!e?.gone) throw e;
        await markInbox(m.id, { gone: true });
        return { ok: false, why: "no longer on the relay", gone: true };
      }
      return { ok: true, name: it.file.name, mime: it.file.mime, data: b64std(data) };
    }
    case "saved": {
      // Chrome took the download: the item is marked and the relay's copy goes.
      const it = (await inbox()).find((x) => x.id === m.id && x.type === "file");
      if (!it) return { ok: false, why: "no such file" };
      await markInbox(m.id, { saved: true });
      const p = await get("pairing");
      if (p) await relay(p, "DELETE", `/files/${it.file.fid}`).catch(() => {});
      return { ok: true };
    }
    case "sendLink": return handoff({ type: "link", url: m.url, open: m.open === true });
    case "sendText": return handoff({ type: "text", text: m.text });
    case "sendFile": {
      let data;
      try { data = fromB64std(String(m.data || "")); } catch { return { ok: false, why: "unreadable file" }; }
      return sendFile(m.name, typeof m.mime === "string" ? m.mime : "", data);
    }
    default: return { ok: false, why: "unknown" };
  }
}

/** The outbox is looked at every 30 s while paired (the phone holds no line open; neither does this). */
async function alarm() {
  try {
    if (await get("pairing")) await chrome.alarms.create(ALARM, { periodInMinutes: 0.5 });
    else await chrome.alarms.clear(ALARM);
  } catch { /* tests */ }
}

const MENU = [
  { id: "sphinx.open", title: "Open this page on my phone", contexts: ["page"] },
  { id: "sphinx.link", title: "Send this link to my phone", contexts: ["link"] },
  { id: "sphinx.text", title: "Send the selected text to my phone", contexts: ["selection"] },
];
function menus() {
  try { chrome.contextMenus.removeAll(() => { for (const m of MENU) chrome.contextMenus.create({ ...m, documentUrlPatterns: ["http://*/*", "https://*/*"] }); }); } catch { /* tests */ }
}

/** A right-click menu choice: Chrome hands the page's link, the link or the selection; the page itself sends nothing. */
async function menuClicked(info) {
  if (info.menuItemId === "sphinx.open") return handoff({ type: "link", url: info.pageUrl, open: true });
  if (info.menuItemId === "sphinx.link") return handoff({ type: "link", url: info.linkUrl });
  if (info.menuItemId === "sphinx.text") return handoff({ type: "text", text: String(info.selectionText || "").slice(0, 3000) });
  return { ok: false };
}

chrome.alarms?.onAlarm?.addListener((a) => { if (a.name === ALARM) pollOutbox().catch(() => {}); });
chrome.contextMenus?.onClicked?.addListener((info) => { menuClicked(info).catch(() => {}); });
chrome.notifications?.onClicked?.addListener((id) => { if (id.startsWith("sphinx:")) chrome.tabs.create({ url: chrome.runtime.getURL("popup.html") }); });

// For the tests.
export const _test = { popup, pollOutbox, menuClicked, sendFile, fetchFile, inbox, alarm, held, register, waiting, locked, send, ready, options, trusted, phoneStatus, paint, tabs, trace: () => trace };
