# Sphinx relay

The mailbox between the phone and a paired laptop: one file, `sphinx_relay.py` (FastAPI). It keeps, per pairing, a
pairing id, a 32-byte HMAC key and the phone's hello, and holds sealed blobs in memory for at most 60 seconds. It can't
read a request or a reply, and it never sees a site, a user name or a code. Design: `../docs/DESIGN.md`.

Optionally it also wakes the phone through Firebase Cloud Messaging: with a service account file
(`SPHINX_FCM_ACCOUNT`) and a push token the phone registered for the pairing, each request goes out at once as an FCM
data message carrying the sealed blobs. The phone holds no live connection: without FCM, requests reach it only when
it fetches (the app opened, or its 15-minute heartbeat).

## Run it

On a VPS it runs as its own systemd service behind Caddy: see `../deploy/` (`install.sh`, then
`install-caddy.sh`). Anywhere else:

```
pip install --require-hashes -r requirements.txt
python sphinx_relay.py
```

or with Docker:

```
docker build -t sphinx-relay .
docker run -d --name sphinx-relay -p 127.0.0.1:8080:8080 -v sphinx-relay:/data sphinx-relay
```

The phone and the extension only talk **https**, and the relay's routes live at the root (`/v1/...`), so give it its
own host name and put TLS in front, for example with Caddy:

```
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

The relay's address you then type on the extension's options page is `https://relay.example.com`.

## Settings (environment)

| Variable | Default | What |
|---|---|---|
| `SPHINX_HOST` / `SPHINX_PORT` | `127.0.0.1` / `8080` | Where it listens (the Docker image listens on `0.0.0.0`) |
| `SPHINX_STATE` | `sphinx-relay.json` | The pairings file (`/data/sphinx-relay.json` in Docker) |
| `SPHINX_REGISTER_TOKEN` | required | Registering a pairing and every backup route need it (a backup route also takes a paired phone's signature); type it on the extension's options page and it rides in the pairing QR. The relay refuses to start without it |
| `SPHINX_INSECURE_DEV` | unset | `1` lets the relay start without a token, open to anyone: local testing only, never on a reachable host |
| `SPHINX_MAX_PAIRINGS` | `8` | Pairings the relay keeps |
| `SPHINX_TRUSTED_PROXIES` | `127.0.0.1` | Proxies whose `X-Forwarded-*` headers are believed |
| `SPHINX_BACKUP_DIR` | the pairings file's folder | Where the backup slots and the try counts are kept |
| `SPHINX_FCM_ACCOUNT` | empty | Path to a Firebase service account JSON (the Sphinx project's, never another app's). Empty or missing: no FCM wake (requests wait for the phone's next fetch) |

The relay fails closed (review 2026-10-27): without `SPHINX_REGISTER_TOKEN` it refuses to start, unless
`SPHINX_INSECURE_DEV=1` says on purpose that it is a local test relay. Open, anyone could register pairings until the
limit and reach the backup routes. `deploy/install.sh` writes a fresh token to `/etc/sphinx/relay.env`.

## API

All bodies are JSON. Every route except registering a pairing is signed with the pairing's relay key:

```
x-sphinx-pid    the pairing id
x-sphinx-ts     unix seconds (within 60 s of the relay's clock)
x-sphinx-nonce  16-32 url-safe characters, never reused
x-sphinx-sig    b64url(HMAC-SHA256(relay key, "METHOD\npath\nquery\nts\nnonce\nsha256hex(body)"))
```

| Route | Who | What |
|---|---|---|
| `POST /v1/pairings` `{pid, key, hello}` | phone | Register (optional `x-sphinx-token`). Same body again is fine; another key for a known pid is 409 |
| `DELETE /v1/pairings/{pid}` | either | Unpair (signed by that pairing) |
| `GET /v1/inbox` | phone | What is queued now, `{items: [{rid, blob}]}` (no long poll) |
| `POST /v1/inbox/ack` `{rids}` | phone | Remove handled blobs (unacked ones expire after 60 s) |
| `POST /v1/replies` `{rid, blob}` | phone | A sealed reply for the laptop |
| `POST /v1/push` `{token}` | phone | Its FCM token for this pairing (`""` forgets it): `{push}` says whether requests now wake it through FCM |
| `GET /v1/hello` | laptop | The phone's hello, to finish pairing |
| `POST /v1/requests` `{rid, blob}` | laptop | A sealed request for the phone |
| `GET /v1/replies/{rid}` | laptop | Long poll (25 s) for the reply; 204 when none came |
| `POST /v1/outbox` `{rid, blob}` | phone | A sealed handoff for the laptop (direction `'p'`), kept 2 minutes |
| `GET /v1/outbox`, `POST /v1/outbox/ack` `{rids}` | laptop | What the phone sent; acked after reading |
| `PUT /v1/files/{fid}/{n}?of={total}` `{blob}` | either | One ciphertext chunk (512 KiB + 16 at most), written once |
| `GET /v1/files/{fid}/{n}`, `DELETE /v1/files/{fid}` | either | A chunk back (404 when gone); the file dropped once it arrived |
| `GET /v1/status` | laptop | `{paired, phone_seen, push, now}`: when this pairing's phone last made a signed call (to the minute), for the extension's icon |
| `GET /healthz` | anyone | `{ok: true}` |

Limits: 60 signed calls a minute per pairing, 10 requests a minute, 20 queued, 4 KB blobs, 60 s TTL, 4 open reply long polls (the laptop's)
per pairing and 32 in all, nonces bounded per pairing and in all (refused past a bound, never evicted).

The FCM message is exactly `{"t": "sync", "sphinx": "[{pid, rid, blob}, ...]"}`: the pairing's queued blobs, newest
first, as many as fit in 3,500 bytes (else just `{"t": "sync"}` and the phone fetches). High priority, 60 s TTL, no
notification block. Google sees what the relay sees: ciphertext, its size and when it was sent.

File chunks live in memory only, never on disk: at most 16 chunks a file (8 MiB), 24 MiB a pairing, 64 MiB in all,
10 minutes each. Past a cap the upload is refused (507), nothing is evicted. These protect the relay's memory from a
paired device, or a stolen pairing key, that uploads without end. Caddy allows request bodies up to 1 MB for the chunks.

## Backup

| Route | Who | What |
|---|---|---|
| `GET /v1/backup/pass/salt` | a phone | The passcode's public Argon2id salt and cost (counted as a try when there is none) |
| `POST /v1/backup/{slot}/open` `{auth}` | a phone | The slot's ciphertext, when `auth` matches its verifier |
| `PUT /v1/backup/{slot}` `{auth, new_auth?, salt?, kdf?, blob, create?}` | the phone | Create or update (needs the slot's `auth`); `create: false` only updates, a missing slot is 404 |
| `POST /v1/backup/{slot}/delete` `{auth}` | the phone | Remove a slot |

Every backup route needs `x-sphinx-token` (when the relay has one) or a paired phone's signed headers; without either,
403 before any try is counted.

`{slot}` is `pass` or a recovery phrase's id (one at a time). Stored on disk in `SPHINX_BACKUP_DIR` (default: the
pairings file's folder): `backup.json` (per slot a verifier, the salt and cost, the ciphertext), `backup-guard.json`
(the try counts, per slot) and, when a slot is locked, `backup.<slot>.locked`. Every wrong `auth` counts: 3 free per
client IP then 30 s doubling, 10 free per slot then 60 s doubling (each at most a day), and after 25 in a row that slot
locks until `rm /var/lib/sphinx/backup.<slot>.locked` on the VPS (an old `backup.locked` locks every slot). The client IP behind Caddy's unix socket is Caddy's X-Forwarded-For.
Anyone with `backup.json` can guess passcodes offline, limited only by the passcode and Argon2id's cost.

## Dependencies

Pinned with hashes: `requirements.in` -> `requirements.txt` (and `requirements-dev.in` -> `requirements-dev.txt`) with
`uv pip compile --generate-hashes --universal --python-version 3.12 --no-emit-index-url`. Install with
`--require-hashes`. `cryptography` is only for the FCM sign-in (a JWT signed with the service account's key).

## Tests

```
pip install --require-hashes -r requirements-dev.txt
pytest
```
