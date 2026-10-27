// Sphinx on a page: find a one-time-code field (detect.js), and as soon as it is there on a site saved on the phone,
// ask the phone (once per page on its own; each click into it asks again when none is waiting). The phone asks for his fingerprint; the code comes back,
// is typed into the field (or its boxes), and the form it's in is submitted (his fingerprint was the yes), except a code
// from an SMS or email, which is only typed in. A small note next to the field says what is happening. Earlier still,
// when the sign-in page opens with a visible password field (or, as fallbacks, when his password goes in: typed,
// autofilled or submitted), it asks the phone to have the code ready (code.ready).
// It trusts nothing from the page: no postMessage or custom-event listener, no page script injected, only the DOM read
// a focus listener, and a change listener that remembers the user name he types. The site the code is for comes from Chrome (sender.tab.url) in the service worker, never from
// here; the only page-derived thing sent is the visible user name, as a hint, capped there at 120 characters.
(() => {
  const D = globalThis.SphinxDetect;
  let eligible = null;
  const armed = new WeakSet();

  const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== "hidden"; };
  const labelOf = (el) => (el.labels && el.labels[0]?.innerText) || el.closest("label")?.innerText || "";
  const desc = (el) => ({
    type: el.type, autocomplete: el.getAttribute("autocomplete"), name: el.name, id: el.id, ariaLabel: el.getAttribute("aria-label"),
    placeholder: el.placeholder, label: labelOf(el), inputMode: el.inputMode, maxLength: el.maxLength > 0 ? el.maxLength : undefined,
    pattern: el.getAttribute("pattern"),
    // Only a field that can hold a user name gives its value; never a password.
    value: el.type === "password" || el.type === "hidden" ? "" : el.value,
  });

  /** The code target: a single field, or the boxes of a split one (4-8 single-character inputs under one parent). */
  function find() {
    const inputs = [...document.querySelectorAll("input")].filter((el) => !el.disabled && !el.readOnly && visible(el));
    const single = inputs.find((el) => el.maxLength !== 1 && D.isOtp(desc(el)));
    if (single) return { fields: [single] };
    const ones = inputs.filter((el) => el.maxLength === 1);
    const byParent = new Map();
    for (const el of ones) {
      let p = el.parentElement;
      for (let i = 0; i < 3 && p && ones.filter((o) => p.contains(o)).length < 4; i++) p = p.parentElement;
      if (p) byParent.set(p, [...(byParent.get(p) || []), el]);
    }
    for (const group of byParent.values()) if (D.isSplit(group.map(desc))) return { fields: group };
    return null;
  }

  function setValue(el, v) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // Our own focus() after typing a code in is not his click: it never asks again.
  let quiet = false;
  function fill(target, code) {
    quiet = true;
    try { fillIn(target, code); } finally { quiet = false; }
  }
  function fillIn(target, code) {
    if (target.fields.length === 1) { setValue(target.fields[0], String(code)); target.fields[0].focus(); return; }
    const digits = D.splitDigits(code, target.fields.length);
    target.fields.forEach((el, i) => setValue(el, digits[i] || ""));
    target.fields[Math.min(digits.length, target.fields.length) - 1]?.focus();
  }

  let note;
  function say(el, text, keep = false) {
    if (!note) {
      note = document.createElement("div");
      note.setAttribute("role", "status");
      // Basalt with a jade "Sphinx" cartouche tag (a pill with a short bar near its right end), as in the app.
      Object.assign(note.style, {
        position: "absolute", zIndex: 2147483647, font: "500 12.5px/16px system-ui, sans-serif", color: "#f2f2f2", background: "#0a0a0a",
        border: "1px solid rgba(255,255,255,.10)", borderRadius: "10px", padding: "6px 12px 6px 7px", pointerEvents: "none", maxWidth: "320px",
        display: "flex", alignItems: "center", gap: "8px",
      });
      const tag = document.createElement("span");
      tag.textContent = "Sphinx";
      Object.assign(tag.style, { position: "relative", flex: "none", border: "1px solid #7fd6aa", borderRadius: "999px", padding: "0 13px 0 8px", color: "#7fd6aa", fontSize: "11.5px", lineHeight: "16px" });
      const tie = document.createElement("span");
      Object.assign(tie.style, { position: "absolute", right: "5px", top: "4px", bottom: "4px", width: "1px", background: "#7fd6aa" });
      tag.appendChild(tie);
      note.append(tag, document.createElement("span"));
      document.documentElement.appendChild(note);
    }
    const r = el.getBoundingClientRect();
    note.style.left = `${window.scrollX + r.left}px`;
    note.style.top = `${window.scrollY + r.bottom + 4}px`;
    note.lastChild.textContent = text;
    clearTimeout(note._t);
    if (!keep) note._t = setTimeout(() => { note?.remove(); note = null; }, 5000);
  }

  // The user name he types on a sign-in page, kept in this tab for this site only (sessionStorage), as the same hint.
  const KEY = "sphinx.user";
  const remembered = () => { try { return sessionStorage.getItem(KEY) || null; } catch { return null; } };
  document.addEventListener("change", (e) => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement)) return;
    const v = D.userHint([desc(el)], "");
    if (v) {
      try { sessionStorage.setItem(KEY, v.slice(0, 120)); } catch { /* storage off: no hint */ }
      // And for the saved site as a whole, so a sign-in that moves host (AWS's regional pages) still knows who it is.
      send({ t: "remember", user: v });
    }
  }, true);

  const send = (m) => new Promise((ok) => chrome.runtime.sendMessage(m, (r) => ok(chrome.runtime.lastError ? { ok: false, why: chrome.runtime.lastError.message } : r)));

  // One request in flight at a time; `filled` once a code went in; `ended` is why the last one ended without a code.
  let busy = false, filled = false, ended = null, filledAt = 0;
  const auto = new Set();   // the pages (URLs) of this document already asked for on their own: once each, never per DOM change
  const may = (trigger, t) => D.shouldAsk({ trigger, busy, filled, autoDone: auto.has(location.href), ended,
    sinceFill: filled ? Date.now() - filledAt : Infinity, fieldEmpty: !t || !t.fields.some((f) => f.value) });

  async function go(target, trigger) {
    busy = true;
    filled = false;
    try { ended = await ask(target, trigger); } finally { busy = false; }
  }

  /** The code goes in; his fingerprint was the yes, so the form is sent on too, except a texted code (typed in only). */
  function done(target, at, w) {
    fill(target, w.code);
    filled = true;
    filledAt = Date.now();
    // A texted code (SMS or email) is typed in only, never submitted (the owner, 2026-10-25): he checks it first.
    if (w.via === "text") { say(at, "Sphinx: filled from your texted code. Check it and continue."); return null; }
    // His fingerprint was the yes, so the code is sent on too (the owner, 2026-10-23): the form the code box is in is
    // submitted, as pressing Enter would, never a guessed button (it could be Cancel or "try another way").
    const form = at.form || at.closest("form");
    // Only a form that posts back to this page's own origin: one the page points elsewhere (an injected form) gets the
    // code typed in, never sent (review 2026-10-27).
    // Read and submit through the prototypes: a field named "action", "getAttribute" or "requestSubmit" can shadow them.
    // requestSubmit() with no submitter posts to the form's own action (no button's formaction applies). Checked again
    // right before the submit: the page may change the action in between.
    const onHome = () => !!form && D.sameOrigin(Element.prototype.getAttribute.call(form, "action") ?? "", location.origin, document.baseURI);
    const sent = onHome() && (() => { try { setTimeout(() => { if (onHome()) HTMLFormElement.prototype.requestSubmit.call(form); }, 300); return true; } catch { return false; } })();
    say(at, `Sphinx: filled${w.account ? ` (${w.account})` : ""}${sent ? " and sent" : ". Check it and continue"}.`);
    return null;
  }

  /** One request: returns why it ended without a code ("expired", "denied", "no answer", ...), or null once filled. */
  async function ask(target, trigger) {
    const at = target.fields[0];
    // The code page often doesn't show who is signing in (GitHub's doesn't): fall back to the user name he typed on this
    // site's sign-in page in this tab, so the phone picks between his two accounts itself (the owner, 2026-10-23).
    const user = D.userHint([...document.querySelectorAll("input")].map(desc), document.body?.innerText || "") || remembered();
    // When the field was first seen, for the worker's timing trace (the gap from seen to asked).
    const r = await send({ t: "ask", user, seen: seenAt, trigger });
    if (!r?.ok) return "error";
    if (r.code) return done(target, at, { code: r.code, account: r.account });
    say(at, "Sphinx: answer on your phone", true);
    const end = Date.now() + 75000;
    while (Date.now() < end) {
      const w = await send({ t: "wait", rid: r.rid });
      if (w?.done) {
        if (w.ok && w.code) return done(target, at, w);
        say(at, w.why === "denied" ? "Sphinx: denied on the phone" : w.why === "no account" ? "Sphinx: no account for this site"
          : w.why === "expired" ? "Sphinx: the request expired. Click the field to ask again." : `Sphinx: no code (${w.why || "refused"})`);
        return w.why === "expired" ? "expired" : w.why === "no such request" ? "error" : w.why || "refused";
      }
      if (w?.ok === false) { say(at, `Sphinx: ${w.why}`); return "error"; }
    }
    say(at, "Sphinx: the phone didn't answer. Click the field to ask again.");
    return "no answer";
  }

  let seenAt = 0, skipped = false;
  async function scan() {
    const target = find();
    if (!target) return;
    if (!seenAt) seenAt = Date.now();
    if (eligible === null) eligible = !!(await send({ t: "eligible" }))?.ok;
    if (!eligible) return;
    // A click asks again whenever none is in flight (shouldAsk), after a fill too (the site may turn a code down); armed once per field element.
    // A click counts too: after a fill the field keeps focus, so clicking it again fires no focus event.
    // Only his real gesture (isTrusted): a page script calling focus() or click() in a loop can't flood his phone with
    // fingerprint prompts (security review 2026-10-26).
    const again = (e) => { const t = find() || target; if (e.isTrusted && !quiet && may("focus", t)) go(t, "focus"); };
    target.fields.filter((el) => !armed.has(el)).forEach((el) => { armed.add(el); el.addEventListener("focus", again); el.addEventListener("click", again); });
    // And as soon as the field is there, once per page (the owner, 2026-10-25): the phone asks while he reaches for it.
    if (may("seen")) { auto.add(location.href); go(target, "seen"); }
    // Refused on sight: the worker's trace gets the gate's flags once (2026-10-27: a field stood 8 s before his click asked).
    else if (!skipped) { skipped = true; send({ t: "seen", busy, filled, autoDone: auto.has(location.href), fields: target.fields.length }); }
  }

  // The sign-in has started (owner, 2026-10-26: "prefetch the code ... when password is being entered or autofilled"):
  // a password field holds a value, so the phone asks him now (code.ready) and the code field's own request later is
  // answered at once. Once per page; only his own input or submit, or our read of an autofill after load (shouldReady).
  // Nothing from the page goes with it but the same user name hint; the site comes from Chrome in the service worker.
  // The page loaded on a saved site: the worker shows it (the icon's green dot) and says whether it may ask.
  send({ t: "eligible" }).then((r) => { if (eligible === null) eligible = !!r?.ok; });
  let readied = false;
  const passwords = () => [...document.querySelectorAll('input[type="password"]')];
  // Chrome keeps an autofilled password's value from the page until his first click on it, but marks the field
  // :autofill, which a page script can't set (owner, 2026-10-26: autofill wasn't seen until he clicked the field).
  const autofilled = (el) => { try { return el.matches(":autofill"); } catch { try { return el.matches(":-webkit-autofill"); } catch { return false; } } };
  async function ready(trigger, trusted, at) {
    console.log("SPHINX", new Date().toISOString().slice(11, 23), "ready?", trigger, "done", readied, "field", passwords().some(visible), "visible", document.visibilityState);
    if (!D.shouldReady({ trigger, trusted, done: readied, filled, value: passwords().some((el) => el.value || autofilled(el)),
      field: passwords().some(visible), visible: document.visibilityState === "visible" })) return;
    readied = true;
    if (eligible === null) eligible = !!(await send({ t: "eligible" }))?.ok;
    if (!eligible) return;
    const el = at || passwords().find((p) => p.value || autofilled(p)) || passwords().find(visible);
    const user = D.userHint([...document.querySelectorAll("input")].map(desc), "") || remembered();
    if (el) say(el, "Sphinx: approve on your phone to have the code ready", true);
    console.log("SPHINX", new Date().toISOString().slice(11, 23), "asking the phone (ready)");
    const r = await send({ t: "ready", user });
    console.log("SPHINX", new Date().toISOString().slice(11, 23), "ready answer", JSON.stringify(r));
    if (el && document.contains(el)) say(el, r?.ok ? "Sphinx: the code is ready for 60 s" : `Sphinx: not ready (${r?.why || "no answer"})`);
  }
  const onPassword = (e) => { if (e.target instanceof HTMLInputElement && e.target.type === "password") ready(e.type, e.isTrusted, e.target); };
  document.addEventListener("input", onPassword, true);
  document.addEventListener("change", onPassword, true);
  document.addEventListener("submit", (e) => ready("submit", e.isTrusted, null), true);
  // An autofill after load: Chrome fills a moment after the page, sometimes after its fields appear, so look a few times.
  for (const ms of [300, 800, 1500, 3000, 6000]) setTimeout(() => ready("load", true, null), ms);
  // Earlier still (owner, 2026-10-26: "ask when the sign-in page opens"): a visible password field on a visible page
  // asks at once, without waiting for a value; the triggers above stay as fallbacks (no-ops once readied). Looked for
  // now, as the page changes (a field drawn late), and when a background tab comes to the front.
  const page = () => ready("page", true, null);
  page();
  document.addEventListener("visibilitychange", page);

  let timer, frame = 0;
  const later = () => { clearTimeout(timer); timer = setTimeout(() => { page(); scan(); }, 400); };
  // The first look for a code field runs on the very change that drew it, one look per frame, until this page has
  // asked (owner, 2026-10-27: the 400 ms quiet wait showed as lag before the code went in). The quiet wait stays for
  // arming fields drawn later.
  const soon = () => { if (frame || auto.has(location.href) || busy) return; frame = requestAnimationFrame(() => { frame = 0; scan(); }); };
  later();
  // The page check runs on every change, not only after the page goes quiet: a busy page (AWS redraws for seconds) kept
  // pushing the debounced one back (2026-10-27, measured ~6 s). ready() is a no-op once readied, so this is cheap.
  new MutationObserver(() => { if (!readied) page(); soon(); later(); }).observe(document.documentElement, { childList: true, subtree: true });
})();
