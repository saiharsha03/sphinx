import { draw } from "./qr.js";
import { patterns, setPsl } from "./domains.js";
import { relayOrigin } from "./relay.js";

const $ = (id) => document.getElementById(id);
const send = (m) => chrome.runtime.sendMessage(m);
// Your relay's address (set it here once, or type it on the options page).
const DEFAULT_RELAY = "";
let polling = null, saved = [];

async function render() {
  setPsl(await (await fetch(chrome.runtime.getURL("public_suffix_list.dat"))).text());
  const s = await send({ t: "status" });
  $("paired").hidden = !s.paired;
  $("pair").hidden = s.paired;
  if (!$("relay").value) $("relay").value = s.relay || DEFAULT_RELAY;
  // This laptop's own relay token, from local.json beside the extension (written from Secrets, never in git), so
  // pairing needs no typing (owner, 2026-10-26). Absent file: the box stays empty, as before.
  if (!$("token").value) {
    try {
      const local = await (await fetch(chrome.runtime.getURL("local.json"))).json();
      if (typeof local.token === "string") $("token").value = local.token.trim();
    } catch { /* no local.json */ }
  }
  if (s.paired) {
    saved = s.domains;
    $("pairedName").textContent = s.name || "This laptop";
    $("pairedRelay").textContent = s.relay;
    // The same state as the toolbar icon, with when the relay last saw the phone.
    const ago = s.phone?.ago;
    const when = typeof ago === "number" ? (ago < 90 ? "a minute ago" : ago < 5400 ? `${Math.round(ago / 60)} minutes ago` : `${Math.round(ago / 3600)} hours ago`) : null;
    $("phone").textContent = s.phone?.state === "reachable" ? `Phone reachable, seen ${when}.`
      : when ? `Phone asleep or offline, last seen ${when}. A request still wakes it.` : "Phone not seen yet (or the relay didn't answer).";
    $("domains").replaceChildren(...(saved.length ? saved : ["None yet: add sites to an account in Sphinx"]).map((d) => Object.assign(document.createElement("li"), { textContent: d })));
    $("domainsAt").textContent = s.domainsAt ? `Updated ${new Date(s.domainsAt).toLocaleString()}` : "";
    const missing = saved.filter((d) => !patterns(d).every((p) => s.granted.includes(p)));
    $("grants").textContent = saved.length ? (missing.length ? `Not allowed yet: ${missing.join(", ")}` : "Allowed on every saved site.") : "";
    $("allow").hidden = missing.length === 0;
    stop();
  } else if (s.pending && s.qr) show(s.qr);
}

function show(qr) {
  draw($("qr"), qr, 6);
  $("qr").hidden = false;
  $("wait").hidden = false;
  if (!polling) polling = setInterval(async () => { const r = await send({ t: "hello" }); if (r?.paired) render(); }, 2500);
}

function stop() { clearInterval(polling); polling = null; $("qr").hidden = true; $("wait").hidden = true; }

$("show").onclick = async () => {
  $("problem").textContent = "";
  const relay = relayOrigin($("relay").value);
  if (!relay) { $("problem").textContent = "The relay must be an https address with no path, like https://relay.example.com"; return; }
  // Chrome asks to allow the relay itself (a click is needed for the prompt); nothing else is reachable.
  if (!(await chrome.permissions.request({ origins: [`${relay}/*`] }))) { $("problem").textContent = "Sphinx can't reach the relay without that permission."; return; }
  const r = await send({ t: "offer", name: $("name").value, relay, token: $("token").value });
  if (r?.qr) show(r.qr); else $("problem").textContent = r?.why || "No pairing code.";
};
// Chrome asks to allow exactly the saved sites (a click is needed for the prompt).
$("allow").onclick = async () => { if (await chrome.permissions.request({ origins: saved.flatMap(patterns) })) await send({ t: "granted" }); render(); };
$("refresh").onclick = async () => { $("domainsAt").textContent = "Asking the phone"; await send({ t: "refresh" }); render(); };
$("unpair").onclick = async () => { if (confirm("Unpair this laptop? Also unpair it on the phone (Sphinx, Laptops).")) { await send({ t: "unpair" }); render(); } };
render();
