import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import "../detect.js";
import { allowed, matches, normalize, patterns, savable, setPsl } from "../domains.js";

const { isOtp, isSplit, splitDigits, userHint, shouldAsk, shouldReady, sameOrigin } = globalThis.SphinxDetect;

test("a code is submitted only to a form that posts back to the page's own origin", () => {
  const o = "https://github.com";
  assert.equal(sameOrigin("https://github.com/sessions/two-factor", o), true);
  assert.equal(sameOrigin("/sessions/two-factor", o), true);
  // An injected form pointed elsewhere, a look-alike, another scheme or port: typed in, never sent.
  for (const a of ["https://evil.example/c", "https://github.com.evil.example/", "http://github.com/x", "https://github.com:8443/x", "javascript:alert(1)", "data:text/html,x"])
    assert.equal(sameOrigin(a, o), false, a);
  // No action: the page itself. A relative one resolves against the document's base (a <base> the page set).
  assert.equal(sameOrigin("", o, "https://github.com/login"), true);
  assert.equal(sameOrigin("collect", o, "https://evil.example/"), false);
  // A clobbered form.action is an element, not the attribute: never taken.
  assert.equal(sameOrigin({ toString: () => "/x" }, o), false);
  const src = readFileSync(new URL("../content.js", import.meta.url), "utf8");
  assert.match(src, /Element\.prototype\.getAttribute\.call\(form, "action"\)/);
  // Checked again right before the submit, and submitted through the prototype.
  assert.match(src, /setTimeout\(\(\) => \{ if \(onHome\(\)\) HTMLFormElement\.prototype\.requestSubmit\.call\(form\); \}/);
  assert.doesNotMatch(src, /form\.action\b/);
});

test("tells the phone a sign-in started once a password is in: his own input or submit, or an autofill read after load", () => {
  const s = (o) => ({ trusted: true, done: false, filled: false, value: true, field: true, visible: true, ...o });
  for (const trigger of ["input", "change", "submit", "load"]) assert.equal(shouldReady(s({ trigger })), true, trigger);
  // A page script's synthetic events never fire it (so it can't loop his phone), our own load read does.
  for (const trigger of ["input", "change", "submit"]) assert.equal(shouldReady(s({ trigger, trusted: false })), false, trigger);
  assert.equal(shouldReady(s({ trigger: "load", trusted: false })), true);
  assert.equal(shouldReady(s({ trigger: "input", value: false })), false);     // an empty password field
  assert.equal(shouldReady(s({ trigger: "input", done: true })), false);       // once per page
  assert.equal(shouldReady(s({ trigger: "input", filled: true })), false);     // a code already went in
  assert.equal(shouldReady(s({ trigger: "focus" })), false);
});

test("asks as soon as a visible sign-in page opens, before any password is in (the owner, 2026-10-26)", () => {
  const s = (o) => ({ trigger: "page", trusted: true, done: false, filled: false, value: false, field: true, visible: true, ...o });
  assert.equal(shouldReady(s()), true);
  assert.equal(shouldReady(s({ field: false })), false);        // no password field: already signed in
  assert.equal(shouldReady(s({ done: true })), false);          // once per page; the value triggers are no-ops after it
  assert.equal(shouldReady(s({ trigger: "input", done: true, value: true })), false);
  // A background tab never prompts, whatever the trigger.
  for (const trigger of ["page", "load", "input", "submit"]) assert.equal(shouldReady(s({ trigger, value: true, visible: false })), false, trigger);
});

test("asks once on its own when the field appears, and on every click while none is in flight", () => {
  const s = (o) => ({ busy: false, filled: false, autoDone: false, ...o });
  assert.equal(shouldAsk(s({ trigger: "seen" })), true);                                   // page load / field appears
  assert.equal(shouldAsk(s({ trigger: "seen", autoDone: true })), false);                  // a DOM change: never again
  assert.equal(shouldAsk(s({ trigger: "seen", filled: true })), false);
  assert.equal(shouldAsk(s({ trigger: "seen", busy: true })), false);
  assert.equal(shouldAsk(s({ trigger: "focus", autoDone: true, busy: true })), false);     // one in flight
  // the owner, 2026-10-26: no waiting a minute: denied, expired, or a code the site turned down, a click asks again.
  for (const ended of ["expired", "no answer", "error", "denied", "no account", null]) assert.equal(shouldAsk(s({ trigger: "focus", autoDone: true, ended })), true, String(ended));
  assert.equal(shouldAsk(s({ trigger: "focus", autoDone: true, filled: true })), true);
  // 2026-10-27: a click within 5 s of a fill, the code still in the field, asks nothing; the field cleared, or later, asks.
  assert.equal(shouldAsk(s({ trigger: "focus", autoDone: true, filled: true, sinceFill: 1400, fieldEmpty: false })), false);
  assert.equal(shouldAsk(s({ trigger: "focus", autoDone: true, filled: true, sinceFill: 1400, fieldEmpty: true })), true);
  assert.equal(shouldAsk(s({ trigger: "focus", autoDone: true, filled: true, sinceFill: 5000, fieldEmpty: false })), true);
  assert.equal(shouldAsk(s({ trigger: "focus", autoDone: true, filled: false, sinceFill: 1400, fieldEmpty: false })), true);
});

test("finds one-time-code fields", () => {
  for (const d of [
    { autocomplete: "one-time-code" },
    { name: "otp" }, { id: "totp" }, { name: "app_otp" }, { id: "mfaCode" }, { name: "2fa_code" },
    { ariaLabel: "Verification code" }, { placeholder: "Enter your 6-digit security code" },
    { label: "Authentication code", name: "x" }, { name: "code", maxLength: 6 }, { name: "code", inputMode: "numeric" },
    { inputMode: "numeric", maxLength: 6 }, { type: "tel", maxLength: 8 }, { pattern: "\\d{6}", maxLength: 6 },
    { name: "otp", type: "password" },
  ]) assert.ok(isOtp(d), JSON.stringify(d));
});

test("leaves other fields alone", () => {
  for (const d of [
    { name: "username" }, { type: "email", name: "otp_email" }, { name: "password", type: "password" }, { name: "zip", maxLength: 6, inputMode: "numeric" },
    { name: "phone", inputMode: "numeric", maxLength: 8 }, { name: "card_cvc", maxLength: 6 }, { name: "promo_code" }, { name: "code" },
    { type: "hidden", name: "otp" }, { name: "q", type: "search" }, { autocomplete: "postal-code", maxLength: 6, inputMode: "numeric" },
    { name: "captcha_code", maxLength: 6 }, { inputMode: "numeric", maxLength: 6, type: "password" }, { name: "country code", inputMode: "numeric" },
  ]) assert.ok(!isOtp(d), JSON.stringify(d));
});

test("split one-box-per-digit fields", () => {
  const box = (extra = {}) => ({ maxLength: 1, inputMode: "numeric", ...extra });
  assert.ok(isSplit(Array.from({ length: 6 }, () => box())));
  assert.ok(isSplit(Array.from({ length: 8 }, () => box())));
  assert.ok(isSplit([box({ ariaLabel: "Digit 1 of verification code" }), box(), box(), box()]));
  assert.ok(!isSplit(Array.from({ length: 4 }, () => box())));         // a PIN-like four with nothing saying "code"
  assert.ok(!isSplit(Array.from({ length: 3 }, () => box())));
  assert.ok(!isSplit([box(), box(), box(), box(), box(), { maxLength: 2 }]));
  assert.deepEqual(splitDigits("123 456", 6), ["1", "2", "3", "4", "5", "6"]);
  assert.deepEqual(splitDigits("12345678", 6), ["1", "2", "3", "4", "5", "6"]);
});

test("the user name hint", () => {
  assert.equal(userHint([{ autocomplete: "username", value: "work@example.com" }], ""), "work@example.com");
  assert.equal(userHint([{ name: "login", value: "harsha-work" }], ""), "harsha-work");
  assert.equal(userHint([], "Two-factor authentication. Signed in as harsha-dev"), "harsha-dev");
  assert.equal(userHint([], "Enter the code sent for your account"), null);
  assert.equal(userHint([], "Hi, h.rudra@example.org! Enter the code."), "h.rudra@example.org");
  assert.equal(userHint([{ name: "otp", value: "123" }], "nothing"), null);
  // A password is never a hint, whatever its field is called.
  assert.equal(userHint([{ type: "password", name: "account_password", value: "hunter2" }], ""), null);
});

const PSL = readFileSync(new URL("../public_suffix_list.dat", import.meta.url), "utf8");
setPsl(PSL);

test("domain guard: an exact host by default, subdomains only for a *. site", () => {
  const g = [["github.com"]];
  for (const h of ["github.com", "www.github.com", "GitHub.com", "github.com."]) assert.ok(allowed(h, h, g), h);
  for (const h of ["gist.github.com", "github.com.evil.io", "evilgithub.com", "github.co", "githubcom", "github.com-login.net", "xn--gthub-cta.com", "github.io", "127.0.0.1", ""])
    assert.ok(!allowed(h, h, g), h);
  assert.ok(matches("gist.github.com", "*.github.com") && matches("github.com", "*.github.com") && !matches("github.com.evil.io", "*.github.com"));
  assert.equal(normalize("https://WWW.GitHub.com:443/login?x=1"), "github.com");
  assert.deepEqual(patterns("github.com"), ["https://github.com/*", "https://www.github.com/*"]);
  assert.deepEqual(patterns("*.example.com"), ["https://example.com/*", "https://*.example.com/*"]);
  assert.deepEqual(patterns("co.id"), []);
});

test("public suffixes from the real list, private ones and exception rules included", () => {
  for (const d of ["co.uk", "co.id", "eu.org", "github.io", "*.github.io", "vercel.app", "com", "foo.ck", "*.co.id", "s3.amazonaws.com"]) assert.equal(savable(d), null, d);
  for (const [d, want] of [["harsha.github.io", "harsha.github.io"], ["bbc.co.uk", "bbc.co.uk"], ["www.ck", "ck"], ["city.kawasaki.jp", "city.kawasaki.jp"], ["wordpress.com", "wordpress.com"], ["*.example.eu.org", "*.example.eu.org"]])
    assert.equal(savable(d), want === "ck" ? null : want, d);
  assert.ok(!matches("someone-else.github.io", "github.io"));
  assert.ok(!matches("anything.com", "com"));
  // *. may not reach over a public suffix below it: a wildcard rule's base, or any rule's parent.
  for (const d of ["*.compute.amazonaws.com", "*.kawasaki.jp", "*.amazonaws.com", "*.blogspot.com"]) assert.equal(savable(d), null, d);
  assert.equal(savable("kawasaki.jp"), "kawasaki.jp");                    // the exact host is still a site
  assert.equal(savable("*.github.com"), "*.github.com");
});

test("tab and frame must be sites of the same account", () => {
  const groups = [["github.com"], ["gitlab.com"]];
  assert.ok(allowed("github.com", "github.com", groups));
  assert.ok(!allowed("github.com", "gitlab.com", groups));              // a frame on another saved site gets nothing
  assert.ok(allowed("github.com", "gitlab.com", [["github.com", "gitlab.com"]]));
});

test("the suffix list is the phone's own file", () => {
  const kt = readFileSync(new URL("../../app/src/main/resources/sphinx/public_suffix_list.dat", import.meta.url), "utf8");
  assert.equal(kt.replace(/\r/g, ""), PSL.replace(/\r/g, ""));
  assert.match(PSL, /\/\/ ===BEGIN PRIVATE DOMAINS===/);
});
