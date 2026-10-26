#!/bin/bash
# Installs (or updates) the Sphinx relay on the VPS, as root, from a checkout of this repo:
#   git clone <this repo> /root/sphinx-src && bash /root/sphinx-src/deploy/install.sh [path/to/fcm-service-account.json]
# Its own Linux user (sphinx, no login), venv (/opt/sphinx), settings (/etc/sphinx), state (/var/lib/sphinx) and socket
# (/run/sphinx-relay). Nothing is shared with any other service. Caddy is a separate step: install-caddy.sh.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
FCM="${1:-}"

id sphinx >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/sphinx --no-create-home --shell /usr/sbin/nologin sphinx
getent group caddy >/dev/null || { echo "no caddy group: is Caddy installed?"; exit 1; }

# Code and a venv of its own; dependencies only as pinned, hash-checked wheels or sdists.
install -d -o root -g root -m 0755 /opt/sphinx /opt/sphinx/app
install -o root -g root -m 0644 "$SRC/relay/sphinx_relay.py" "$SRC/relay/requirements.txt" /opt/sphinx/app/
[ -x /opt/sphinx/venv/bin/python ] || python3 -m venv /opt/sphinx/venv
/opt/sphinx/venv/bin/pip install --quiet --disable-pip-version-check --no-cache-dir --require-hashes -r /opt/sphinx/app/requirements.txt
chown -R root:root /opt/sphinx

# Settings: a registration token made once (only QRs carrying it can pair), and the optional FCM service account.
install -d -o root -g sphinx -m 0750 /etc/sphinx
if [ ! -f /etc/sphinx/relay.env ]; then
  ( umask 027; printf 'SPHINX_REGISTER_TOKEN=%s\n' "$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')" > /etc/sphinx/relay.env )
  chown root:sphinx /etc/sphinx/relay.env
  echo "made /etc/sphinx/relay.env (the token goes on the extension's options page: grep TOKEN /etc/sphinx/relay.env)"
fi
if [ -n "$FCM" ]; then
  install -o root -g sphinx -m 0640 "$FCM" /etc/sphinx/fcm-service-account.json
  grep -q '^SPHINX_FCM_ACCOUNT=' /etc/sphinx/relay.env || echo 'SPHINX_FCM_ACCOUNT=/etc/sphinx/fcm-service-account.json' >> /etc/sphinx/relay.env
  echo "FCM service account installed: requests will wake the phone through Firebase"
fi

# The socket's directory, made at boot by systemd-tmpfiles: it must exist before the unit's namespace (ReadWritePaths).
echo 'd /run/sphinx-relay 2750 sphinx caddy -' > /etc/tmpfiles.d/sphinx-relay.conf
systemd-tmpfiles --create /etc/tmpfiles.d/sphinx-relay.conf

install -o root -g root -m 0644 "$SRC/deploy/sphinx-relay.service" /etc/systemd/system/sphinx-relay.service
systemctl daemon-reload
systemctl enable --quiet sphinx-relay
systemctl restart sphinx-relay

for i in 1 2 3 4 5 6 7 8 9 10; do [ -S /run/sphinx-relay/relay.sock ] && break; sleep 0.5; done
curl -sf --unix-socket /run/sphinx-relay/relay.sock http://sphinx/healthz && echo "  <- relay up on /run/sphinx-relay/relay.sock"
