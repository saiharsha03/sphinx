# Deploying the relay

The relay runs on your own Linux server behind Caddy, fully on its own: the Linux user `sphinx` (no login), the venv
`/opt/sphinx`, the config `/etc/sphinx`, the data `/var/lib/sphinx`, the systemd unit `sphinx-relay` on a unix socket,
and a Caddy site for its own hostname with its own certificate. It shares nothing with other services on the server.

## Before you start
- A server with Caddy installed (its `caddy` group must exist) and Python 3.12.
- A hostname whose DNS points at the server.
- Your Firebase project's service account JSON (README, "Set it up", step 1). Optional, but without it there is no
  fast wake and the phone only hears about requests when Sphinx is opened.

## Install (as root)
```sh
git clone <this repo> /root/sphinx-src
# from your computer: scp service-account.json root@your-server:/root/sphinx-fcm.json
bash /root/sphinx-src/deploy/install.sh /root/sphinx-fcm.json    # or with no argument: no fast wake
shred -u /root/sphinx-fcm.json                                    # the installed copy is /etc/sphinx/fcm-service-account.json (root:sphinx 0640)
curl -s --unix-socket /run/sphinx-relay/relay.sock http://sphinx/healthz   # {"ok":true}
```

`install.sh` makes the user, installs the code and a venv with `pip --require-hashes`, writes `/etc/sphinx/relay.env`
once with a fresh `SPHINX_REGISTER_TOKEN` (plus `SPHINX_FCM_ACCOUNT` when the account was given), creates the socket
directory through `/etc/tmpfiles.d/sphinx-relay.conf` (it must exist before the unit's sandbox is set up), and installs
and starts the hardened unit (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, no capabilities, write access
only to `/var/lib/sphinx` and `/run/sphinx-relay`).

## Caddy
```sh
SPHINX_HOST=sphinx.yourdomain.example SPHINX_BIND=<public IP> bash /root/sphinx-src/deploy/install-caddy.sh
curl -s https://sphinx.yourdomain.example/healthz        # {"ok":true}, from anywhere
```

It writes `/etc/caddy/sphinx.caddy` (your hostname and bind address filled in), backs up the Caddyfile, adds
`import /etc/caddy/sphinx.caddy`, validates, and reloads; a failed validation restores the backup. Only `/healthz` and
`/v1/*` pass; bodies are capped (1 MB, 10 MB for `/v1/backup/*`); everything else is a plain 404.

`SPHINX_BIND`: if your other Caddy sites use `bind <public IP>`, this one must too, or outside traffic reaches a
different listener and gets an empty 200. With no other sites, `0.0.0.0` (the default) is fine.

## The registration token
`grep REGISTER /etc/sphinx/relay.env`. The relay refuses to start without it (only `SPHINX_INSECURE_DEV=1`, for a
local test relay, runs it open). Pairing a laptop and every backup route need it (a backup route also takes a paired
phone's signature). Put it in the extension's options page (or `extension/local.json`), or build it into the app with
`sphinx.relayTokenFile` (the app sends that built-in value only to the built-in relay's own address).

## Update
`git -C /root/sphinx-src pull && bash /root/sphinx-src/deploy/install.sh && bash /root/sphinx-src/deploy/install-caddy.sh`
(with the same `SPHINX_HOST`/`SPHINX_BIND`). The token and the Firebase account stay.

## The backup lock
After 25 wrong tries in a row at one slot the relay locks that slot (`/var/lib/sphinx/backup.<slot>.locked` appears,
`backup.pass.locked` for the passcode's; restores and uploads of it get 423). Check who was guessing
(`journalctl -u sphinx-relay | grep backup`), then unlock: `rm /var/lib/sphinx/backup.pass.locked` (a `backup.locked`
left from an older relay locks every slot until removed). The backup itself lives in `/var/lib/sphinx/backup.json`
(ciphertext only; whoever holds it can guess passcodes offline, so keep VPS backups of it as private as the VPS).

## Undo
`systemctl disable --now sphinx-relay`, remove the `import /etc/caddy/sphinx.caddy` line and reload Caddy, then
`rm -rf /opt/sphinx /etc/sphinx /var/lib/sphinx /etc/systemd/system/sphinx-relay.service /etc/caddy/sphinx.caddy
/etc/tmpfiles.d/sphinx-relay.conf` and `userdel sphinx`.
