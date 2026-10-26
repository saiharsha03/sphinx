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
      Object.assign(note.style, {
        position: "absolute", zIndex: 2147483647, font: "500 12px/16px system-ui, sans-serif", color: "#f3ead9", background: "#26221d",
        border: "1px solid #e8a33d", borderRadius: "6px", padding: "4px 8px", pointerEvents: "none", maxWidth: "280px",
      });
      document.documentElement.appendChild(note);
    }
    const r = el.getBoundingClientRect();
    note.style.left = `${window.scrollX + r.left}px`;
    note.style.top = `${window.scrollY + r.bottom + 4}px`;
    note.textContent = text;
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
  let busy = false, filled = false, ended = null;
  const auto = new Set();   // the pages (URLs) of this document already asked for on their own: once each, never per DOM change
  const may = (trigger) => D.shouldAsk({ trigger, busy, filled, autoDone: auto.has(location.href), ended });

  async function go(target) {
    busy = true;
    filled = false;
    try { ended = await ask(target); } finally { busy = false; }
  }

  /** The code goes in; his fingerprint was the yes, so the form is sent on too, except a texted code (typed in only). */
  function done(target, at, w) {
    fill(target, w.code);
    filled = true;
    // A texted code (SMS or email) is typed in only, never submitted (owner, 2026-10-25): he checks it first.
    if (w.via === "text") { say(at, "Sphinx: filled from your texted code. Check it and continue."); return null; }
    // His fingerprint was the yes, so the code is sent on too (owner, 2026-10-23): the form the code box is in is
    // submitted, as pressing Enter would, never a guessed button (it could be Cancel or "try another way").
    const form = at.form || at.closest("form");
    const sent = !!form && (() => { try { setTimeout(() => form.requestSubmit ? form.requestSubmit() : form.submit(), 300); return true; } catch { return false; } })();
    say(at, `Sphinx: filled${w.account ? ` (${w.account})` : ""}${sent ? " and sent" : ". Check it and continue"}.`);
    return null;
  }

  /** One request: returns why it ended without a code ("expired", "denied", "no answer", ...), or null once filled. */
  async function ask(target) {
    const at = target.fields[0];
    // The code page often doesn't show who is signing in (GitHub's doesn't): fall back to the user name he typed on this
    // site's sign-in page in this tab, so the phone picks between his two accounts itself (owner, 2026-10-23).
    const user = D.userHint([...document.querySelectorAll("input")].map(desc), document.body?.innerText || "") || remembered();
    const r = await send({ t: "ask", user });
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

  async function scan() {
    const target = find();
    if (!target) return;
    if (eligible === null) eligible = !!(await send({ t: "eligible" }))?.ok;
    if (!eligible) return;
    // A click asks again whenever none is in flight (shouldAsk), after a fill too (the site may turn a code down); armed once per field element.
    // A click counts too: after a fill the field keeps focus, so clicking it again fires no focus event.
    // Only his real gesture (isTrusted): a page script calling focus() or click() in a loop can't flood his phone with
    // fingerprint prompts (security review 2026-10-26).
    const again = (e) => { if (e.isTrusted && !quiet && may("focus")) go(find() || target); };
    target.fields.filter((el) => !armed.has(el)).forEach((el) => { armed.add(el); el.addEventListener("focus", again); el.addEventListener("click", again); });
    // And as soon as the field is there, once per page (owner, 2026-10-25): the phone asks while he reaches for it.
    if (may("seen")) { auto.add(location.href); go(target); }
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
    if (!D.shouldReady({ trigger, trusted, done: readied, filled, value: passwords().some((el) => el.value || autofilled(el)),
      field: passwords().some(visible), visible: document.visibilityState === "visible" })) return;
    readied = true;
    if (eligible === null) eligible = !!(await send({ t: "eligible" }))?.ok;
    if (!eligible) return;
    const el = at || passwords().find((p) => p.value || autofilled(p)) || passwords().find(visible);
    const user = D.userHint([...document.querySelectorAll("input")].map(desc), "") || remembered();
    if (el) say(el, "Sphinx: approve on your phone to have the code ready", true);
    const r = await send({ t: "ready", user });
    if (el && document.contains(el)) say(el, r?.ok ? "Sphinx: the code is ready for 30 s" : `Sphinx: not ready (${r?.why || "no answer"})`);
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

  let timer;
  const later = () => { clearTimeout(timer); timer = setTimeout(() => { page(); scan(); }, 400); };
  later();
  new MutationObserver(later).observe(document.documentElement, { childList: true, subtree: true });
})();
