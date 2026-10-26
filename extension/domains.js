// The phishing guard, the same rule as the phone (app/src/main/java/dev/sphinx/Domains.kt): a saved site is one exact
// host (and its www.), or `*.host` for it and its subdomains when that site was opted in. A saved site may not be a public suffix,
// from the bundled Public Suffix List (public_suffix_list.dat, the same file the phone ships; ICANN and private
// sections, wildcard and exception rules). The phone checks it all again before it answers.

export class Psl {
  constructor(text) {
    this.rules = new Set(); this.wild = new Set(); this.except = new Set(); this.parents = new Set();
    for (const raw of text.split("\n")) {
      const r = raw.trim().split(" ")[0].toLowerCase();
      if (!r || r.startsWith("//")) continue;
      const ascii = (s) => { try { return new URL(`http://${s}`).hostname; } catch { return s; } };
      if (r.startsWith("!")) this.except.add(ascii(r.slice(1)));
      else if (r.startsWith("*.")) this.wild.add(ascii(r.slice(2)));
      else this.rules.add(ascii(r));
    }
    // Every host some rule sits under (a `*.` rule's base included): `*.host` there would cover public suffixes.
    const up = (h) => { for (let x = h; x.includes("."); ) { x = x.slice(x.indexOf(".") + 1); this.parents.add(x); } };
    this.rules.forEach(up); this.except.forEach(up); this.wild.forEach((w) => { this.parents.add(w); up(w); });
  }

  coversSuffixes(host) { return this.parents.has(host); }

  suffix(host) {
    const l = host.split(".");
    for (let i = 0; i < l.length; i++) {
      const c = l.slice(i).join(".");
      if (this.except.has(c)) return l.slice(i + 1).join(".");
      if (this.rules.has(c)) return c;
      if (i + 1 < l.length && this.wild.has(l.slice(i + 1).join("."))) return c;
    }
    return l[l.length - 1];
  }

  isSuffix(host) { return this.suffix(host) === host; }
}

let psl = null;
export const setPsl = (text) => { psl = new Psl(text); return psl; };

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

export function normalize(input) {
  let h = String(input).trim().toLowerCase();
  h = h.includes("://") ? h.slice(h.indexOf("://") + 3) : h;
  h = h.split("/")[0].split("?")[0].split("#")[0];
  h = h.slice(h.lastIndexOf("@") + 1).split(":")[0].replace(/\.+$/, "");
  if (h.startsWith("www.")) h = h.slice(4);
  const labels = h.split(".");
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l)) || /^\d+$/.test(labels[labels.length - 1])) return null;
  return h;
}

export function savable(input) {
  if (!psl) throw new Error("the suffix list isn't loaded");
  const t = String(input).trim().toLowerCase();
  const sub = t.startsWith("*.");
  const host = normalize(sub ? t.slice(2) : t);
  if (!host || psl.isSuffix(host)) return null;
  if (sub && psl.coversSuffixes(host)) return null;
  return sub ? `*.${host}` : host;
}

export function matches(host, saved) {
  const h = normalize(host), d = savable(saved);
  if (!h || !d) return false;
  if (d.startsWith("*.")) { const b = d.slice(2); return h === b || h.endsWith("." + b); }
  return h === d;
}

/** One account's sites must cover both the tab and the frame. `groups` is the phone's list of sites per account. */
export const allowed = (top, frame, groups) => (groups || []).some((g) => g.some((d) => matches(top, d)) && g.some((d) => matches(frame, d)));

/** Chrome match patterns for one saved site: the exact host and its www, or the host and its subdomains for `*.`. */
export function patterns(saved) {
  const d = savable(saved);
  if (!d) return [];
  return d.startsWith("*.") ? [`https://${d.slice(2)}/*`, `https://*.${d.slice(2)}/*`] : [`https://${d}/*`, `https://www.${d}/*`];
}
