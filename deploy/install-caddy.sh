#!/bin/bash
# Puts the relay behind Caddy on its own hostname (SPHINX_HOST, default sphinx.example.com), as root on the VPS, after install.sh:
#   bash /root/sphinx-src/deploy/install-caddy.sh
# Copies the site block to /etc/caddy/sphinx.caddy, imports it from the Caddyfile (backed up first), validates, and
# reloads. A failed validation puts the old Caddyfile back and reloads nothing.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
CF=/etc/caddy/Caddyfile
LINE="import /etc/caddy/sphinx.caddy"

# The address the site listens on. SPHINX_BIND: your server's public IP when your other Caddy sites bind to it too
# (otherwise outside traffic reaches another listener and gets an empty 200).
BIND="${SPHINX_BIND:-0.0.0.0}"
# Your relay's hostname: its DNS record points at this server; Caddy gets its certificate by itself.
HOST="${SPHINX_HOST:-sphinx.example.com}"
sed -E -e "s/^([[:space:]]*)bind .*/\1bind $BIND/" -e "s/^sphinx\.example\.com \{/$HOST {/" "$SRC/deploy/sphinx.caddy" > /etc/caddy/sphinx.caddy
chown root:root /etc/caddy/sphinx.caddy; chmod 0644 /etc/caddy/sphinx.caddy
BAK="$CF.bak-sphinx-$(date -u +%Y%m%dT%H%M%SZ)"
cp -p "$CF" "$BAK"
grep -qxF "$LINE" "$CF" || printf '\n# Sphinx relay (its own host and socket)\n%s\n' "$LINE" >> "$CF"
if ! caddy validate --config "$CF" --adapter caddyfile >/dev/null; then
  cp -p "$BAK" "$CF"
  echo "caddy validate failed: Caddyfile restored from $BAK, nothing reloaded"
  exit 1
fi
systemctl reload caddy
echo "Caddy reloaded (backup: $BAK). Check: curl https://<your relay host>/healthz"
