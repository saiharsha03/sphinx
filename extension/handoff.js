// Handoff between the phone and this laptop (docs/DESIGN.md, "Handoff"): a link, a bit of text or a small file, each
// sealed on the pairing like a code, files in chunks under a key of their own. Nothing that arrives is acted on
// without a click: a link opens, a text is copied, a file is downloaded only from the popup's buttons.

export const CHUNK = 512 * 1024;            // plaintext bytes per file chunk (the relay's CHUNK)
export const MAX_CHUNKS = 16;
export const MAX_FILE = CHUNK * MAX_CHUNKS; // 8 MiB, the relay's per-file cap
export const MAX_TEXT = 3000;               // bytes of UTF-8: the sealed envelope must stay under the relay's 4 KB
export const MAX_URL = 2048;
export const KEEP_MS = 10 * 60 * 1000;      // a received item is listed this long (the relay drops file chunks then too)

const FID = /^[A-Za-z0-9_-]{22}$/, KEY = /^[A-Za-z0-9_-]{43}$/, HEX = /^[0-9a-f]{64}$/, MIME = /^[a-z0-9.+-]{1,60}\/[a-z0-9.+-]{1,60}$/i;
const te = new TextEncoder();

/** An http or https link, normalised, or null: no javascript:, data:, file:, chrome: or a user:password part. */
export function httpUrl(u) {
  if (typeof u !== "string" || !u || u.length > MAX_URL) return null;
  let x;
  try { x = new URL(u.trim()); } catch { return null; }
  if ((x.protocol !== "https:" && x.protocol !== "http:") || x.username || x.password) return null;
  return x.href;
}

/** A file name safe to save under: no folders, no control characters, no leading dots, at most 120 characters. */
export function safeName(n) {
  const s = String(n ?? "").replace(/[\u0000-\u001f\u007f]/g, "").split(/[\\/]/).pop().replace(/^[.\s]+/, "").trim().slice(0, 120);
  return s || "file";
}

/** The chunks a file of [size] bytes takes. */
export const chunksFor = (size) => Math.max(1, Math.ceil(size / CHUNK));

/**
 * A handoff body as it may be sent or shown, or null. {type: "link", url, open} | {type: "text", text} |
 * {type: "file", file: {fid, key, name, mime, size, chunks, sha256}}. `open` marks "continue on the other device".
 */
export function item(b) {
  if (!b || typeof b !== "object") return null;
  if (b.type === "link") {
    const url = httpUrl(b.url);
    return url ? { type: "link", url, open: b.open === true } : null;
  }
  if (b.type === "text") {
    if (typeof b.text !== "string" || !b.text.trim() || te.encode(b.text).length > MAX_TEXT) return null;
    return { type: "text", text: b.text };
  }
  if (b.type === "file") {
    const f = b.file;
    if (!f || typeof f !== "object" || !FID.test(f.fid) || !KEY.test(f.key) || !HEX.test(f.sha256)) return null;
    if (!Number.isInteger(f.size) || f.size < 1 || f.size > MAX_FILE || f.chunks !== chunksFor(f.size)) return null;
    const mime = typeof f.mime === "string" && MIME.test(f.mime) ? f.mime.toLowerCase() : "application/octet-stream";
    return { type: "file", file: { fid: f.fid, key: f.key, name: safeName(f.name), mime, size: f.size, chunks: f.chunks, sha256: f.sha256 } };
  }
  return null;
}

/** What a received item says in one line (the popup and the notification). */
export function label(it) {
  if (it.type === "link") { const h = new URL(it.url).host; return it.open ? `Open ${h}` : `Link: ${h}`; }
  if (it.type === "text") return `Text: ${it.text.slice(0, 60)}${it.text.length > 60 ? "…" : ""}`;
  return `File: ${it.file.name} (${Math.max(1, Math.round(it.file.size / 1024))} KB)`;
}
