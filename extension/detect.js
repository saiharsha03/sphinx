// Finding one-time-code fields, in plain functions over what an input says about itself (content.js reads the DOM
// into these descriptors). A classic script, so the content script and the node tests share it.
(function (root) {
  const OTP = /\b(otp|totp|mfa|2fa|two factor|2 step|one time( pass)?( code| password)?|verification code|verify code|security code|auth(entication|enticator)? code|app code|passcode|sign in code|login code|confirmation code|code)\b/;
  const STRONG = /\b(otp|totp|mfa|2fa|two factor|2 step|one time|verif\w*|authenticat\w*|passcode|security code)\b/;
  const NOT = /\b(phone|mobile|tel|zip|postal|post code|card|cvc|cvv|cc|coupon|promo|gift|discount|referral|search|captcha|country|area code|invite|voucher|sms number)\b/;
  const SKIP_TYPES = new Set(["hidden", "submit", "button", "checkbox", "radio", "file", "image", "reset", "range", "color", "date", "email", "url", "search"]);

  // "verificationCode", "otp_input", "mfa-code" -> "verification code", "otp input", "mfa code"
  const words = (s) => String(s || "").replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_\-.[\]:]+/g, " ").toLowerCase();

  /** d: {type, autocomplete, name, id, ariaLabel, placeholder, label, inputMode, maxLength, pattern}. */
  const text = (d) => [d.name, d.id, d.ariaLabel, d.placeholder, d.label].map(words).join(" | ");
  /** The field's own words say it is a code. */
  const says = (d) => !NOT.test(text(d)) && (STRONG.test(text(d)) || OTP.test(text(d)));

  function isOtp(d) {
    const type = (d.type || "text").toLowerCase();
    if (SKIP_TYPES.has(type)) return false;
    const ac = (d.autocomplete || "").toLowerCase();
    if (ac.split(/\s+/).includes("one-time-code")) return true;
    if (/\b(username|email|tel|cc-|postal|address|name)\b/.test(ac)) return false;
    const t = text(d);
    if (NOT.test(t)) return false;
    const numeric = d.inputMode === "numeric" || type === "tel" || type === "number" || /\\d|\[0-9\]/.test(d.pattern || "");
    const sixOrEight = d.maxLength === 6 || d.maxLength === 8;
    if (STRONG.test(t)) return true;
    // A bare "code" needs a code-sized, numeric field to count.
    if (OTP.test(t)) return sixOrEight || numeric;
    // "6-digit inputs": no words at all, but numeric and exactly code-sized.
    return sixOrEight && numeric && type !== "password";
  }

  /**
   * One box per digit: 4 to 8 single-character inputs side by side under one parent (content.js groups them). True
   * when the group looks like a code: 6 or 8 boxes, or any box that says so itself.
   */
  function isSplit(group) {
    if (group.length < 4 || group.length > 8) return false;
    if (!group.every((d) => d.maxLength === 1 && !SKIP_TYPES.has((d.type || "text").toLowerCase()))) return false;
    return group.length === 6 || group.length === 8 || group.some(says);
  }

  /** The digits for each box of a split field (a code longer than the boxes keeps its first ones). */
  const splitDigits = (code, n) => String(code).replace(/\D/g, "").slice(0, n).split("");

  /**
   * The user name the page shows, for picking between two accounts on one site: a username or email field's value
   * first, then "signed in as ..." style text, then the first email on the page. Null when nothing looks like one.
   */
  function userHint(fields, text) {
    for (const f of fields || []) {
      if (["password", "hidden"].includes(String(f.type || "").toLowerCase())) continue;
      const v = String(f.value || "").trim();
      if (v && v.length <= 120 && /\b(user(name)?|email|login|account)\b/.test(words([f.autocomplete, f.name, f.id].join(" ")))) return v;
    }
    const t = String(text || "").slice(0, 20000);
    const m = t.match(/\b(?:signed in as|logged in as|signing in as|sign in to|account:?|for)\s+@?([\w.+-]+@[\w-]+(?:\.[\w-]+)+|[A-Za-z0-9][\w.-]{1,38})/i);
    if (m && !/^(the|your|this|a|an|security|verification|two|more)$/i.test(m[1])) return m[1];
    const e = t.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/);
    return e ? e[0] : null;
  }

  /**
   * When the content script asks the phone (owner, 2026-10-25: ask as soon as the field is there, not only on focus).
   * trigger "seen": the field was found on this page (load, or it appeared); asks once per page (`autoDone`), so DOM
   * changes never ask again, and not after a fill. trigger "focus": he clicked into it; asks whenever no request is in
   * flight, whatever ended the last one (denied, expired, a code the site turned down): his click is the ask, never held
   * back for a minute (the owner, 2026-10-26). The relay's per-pairing rate (10 a minute) is what protects against a loop.
   */
  /**
   * Whether a form's action attribute ([action], as written: "" posts to the page itself) resolved against [base]
   * (document.baseURI) goes to [origin], the page's own: the only form a code is submitted to. The attribute, never
   * form.action, which an <input name="action"> turns into an element (review 2026-10-27).
   */
  function sameOrigin(action, origin, base = origin) {
    if (typeof action !== "string") return false;
    if (action.trim() === "") return true;
    try { return new URL(action, base).origin === origin; } catch { return false; }
  }

  // A click within REASK_MS of a fill, with the code still in the field (the site is still checking it), asks nothing;
  // the site clearing the field (it turned the code down) asks at once (owner, 2026-10-27: a click 1.4 s after the
  // fill put a third prompt on the phone).
  const REASK_MS = 5000;
  function shouldAsk({ trigger, busy, filled, autoDone, sinceFill = Infinity, fieldEmpty = true }) {
    if (busy) return false;
    if (trigger === "seen") return !autoDone && !filled;
    if (trigger === "focus") return !(filled && sinceFill < REASK_MS && !fieldEmpty);
    return false;
  }

  /**
   * When the content script tells the phone a sign-in has started (code.ready, the owner 2026-10-26: "prefetch the code
   * when password is being entered or autofilled"): a password field holds a value, once per page, never after a code
   * went in. trigger "input", "change" or "submit" counts only for his own (trusted) event, so a page script can't fire
   * it; "load" is our own read of an autofilled value shortly after load. "page" (owner, 2026-10-26: ask when the
   * sign-in page opens) needs no value: a visible password field is enough (none = already signed in). Every trigger
   * needs the page itself visible, so a background tab never puts a prompt on his phone.
   */
  function shouldReady({ trigger, trusted, done, filled, value, field, visible }) {
    if (done || filled || visible !== true) return false;
    if (trigger === "page") return field === true;
    if (!value) return false;
    if (trigger === "load") return true;
    return ["input", "change", "submit"].includes(trigger) && trusted === true;
  }

  root.SphinxDetect = { isOtp, isSplit, splitDigits, userHint, words, shouldAsk, shouldReady, sameOrigin };
  if (typeof module !== "undefined") module.exports = root.SphinxDetect;
})(typeof globalThis !== "undefined" ? globalThis : this);
