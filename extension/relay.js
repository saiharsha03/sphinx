// The relay address, as typed on the options page: an https origin ("https://relay.example.com"), else null. Its routes
// are /v1/..., so a path, query, fragment or user part is refused rather than guessed at.
export function relayOrigin(input) {
  let u;
  try { u = new URL(String(input || "").trim()); } catch { return null; }
  if (u.protocol !== "https:" || u.username || u.password || (u.pathname !== "/" && u.pathname !== "") || u.search || u.hash) return null;
  return u.origin;
}
