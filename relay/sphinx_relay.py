"""Sphinx's relay: the mailbox between a phone and a paired laptop (docs/DESIGN.md). Nothing more.

What it sees: a pairing id, a 32-byte relay key per pairing, the phone's hello, and sealed blobs. Every request and
every reply is AES-256-GCM sealed end to end with keys the phone and the laptop derived from X25519 and a secret that
was only ever in the pairing QR; the relay key is a separate HKDF output of that secret, so holding it opens nothing.
No site, user name or code is ever here in the clear, and nothing about a blob is logged beyond its pairing's first
6 characters.

Registering a pairing is the only unsigned call (gated by SPHINX_REGISTER_TOKEN, which the relay requires to start
unless SPHINX_INSECURE_DEV=1); a pid can't be taken over once registered. Every other call, the phone's and the laptop's alike, proves itself with HMAC-SHA256 under the
pairing's relay key:
  x-sphinx-pid, x-sphinx-ts (unix seconds, within 60 s), x-sphinx-nonce (16-32 url-safe chars, single use),
  x-sphinx-sig = b64url(HMAC(key, "METHOD\\npath\\nquery\\nts\\nnonce\\nsha256hex(body)"))
Both ends hold that key, so the role is the route: the laptop sends requests and waits for replies, the phone long
polls its inbox, acks and replies. Either end could only confuse itself by calling the other's routes; the sealed
direction byte and counters stop a blob from being taken for the other kind.

Queues live in memory: at most 20 blobs per pairing, each 60 s at most, 10 requests a minute per pairing, 4 KB each.
Bounded too: 60 signed calls a minute per pairing (any route), 4 open long polls per pairing and 32 in all, and nonces
(kept 2 minutes) at most 150 per pairing and 1,200 in all; past a bound the call is refused (429), never an older
nonce evicted. A phone blob stays queued until the phone acks it after handling (or its 60 s run out). Pairings are
kept in a small JSON file (SPHINX_STATE, default ./sphinx-relay.json).

Fast wake (optional): with a Firebase service account at SPHINX_FCM_ACCOUNT and a push token the phone registered for
the pairing (POST /v1/push), every queued request also goes out at once as an FCM data message,
{"t": "sync", "sphinx": "[{pid, rid, blob}, ...]"}: the pairing's queued blobs, newest first, as many as fit in
CARRY_MAX bytes (else a plain {"t": "sync"} and the phone fetches). Google then sees what this relay sees: ciphertext,
its size and when it was sent. The phone opens a carried blob exactly like a fetched one, then fetches and acks. Without
the account (or a token) nothing is pushed, and requests reach the phone only when it fetches (the app opened, or its
15-minute heartbeat).
"""
import asyncio
import base64
import binascii
import functools
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

PID = re.compile(r"^[A-Za-z0-9_-]{22}$")          # 16 random bytes, b64url
RID = re.compile(r"^[A-Za-z0-9_-]{16,32}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{16,32}$")
BLOB = re.compile(r"^[A-Za-z0-9_-]{24,5600}$")    # b64url of at most 4 KB
MAX_BLOB = 4096
MAX_QUEUED = 20
TTL_S = 60
WAIT_S = 25
SKEW_S = 60
RATE = 10                 # requests per pairing per RATE_S
RATE_S = 60
MAX_PAIRINGS = int(os.environ.get("SPHINX_MAX_PAIRINGS", "8"))
# Handoff, phone to laptop: sealed blobs wait in the laptop's outbox until its next look (an alarm every 30 s). The
# phone seals them to expire in under 2 minutes; the relay drops them after OUT_TTL_S either way.
OUT_TTL_S = 120
# Handoff files: ciphertext chunks only (each sealed with a per-file key the relay never sees), in memory only, never
# on disk. These caps protect the relay's memory (and so the VPS) from a paired device, or a stolen pairing key, that
# uploads without end: a file is at most FILE_CHUNKS chunks of CHUNK_MAX bytes (8 MiB of plaintext), a pairing holds
# at most PAIR_FILE_BYTES at once, the relay FILE_BYTES_ALL in all, and every chunk is gone after FILE_TTL_S.
CHUNK = 512 * 1024                     # plaintext bytes per chunk
CHUNK_MAX = CHUNK + 16                 # its AES-GCM ciphertext and tag
FILE_CHUNKS = 16
FILE_TTL_S = 600
PAIR_FILE_BYTES = 24 * 1024 * 1024
FILE_BYTES_ALL = 64 * 1024 * 1024
FILE_BODY_MAX = 720_000                # a chunk's JSON body: b64url of CHUNK_MAX bytes plus the wrapping
FID = re.compile(r"^[A-Za-z0-9_-]{22}$")
CALLS = 60                # signed calls per pairing per RATE_S, any route
POLLS = 4                 # open long polls per pairing (the phone's inbox and the laptop's replies)
POLLS_ALL = 32            # and in all
NONCES = 150              # nonces held per pairing (2 * SKEW_S at CALLS a minute is 120)
NONCES_ALL = 1200
# FCM refuses more than 4 KB of data in all; this cap on the carried value leaves room for the key names.
CARRY_MAX = 3500
PUSH_TOKEN = re.compile(r"^[A-Za-z0-9_:.-]{20,512}$")
SEEN_ROUND_S = 60         # the phone's last call, as the laptop's status shows it: to the minute, no finer
FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"

log = logging.getLogger("sphinx.relay")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(method: str, path: str, query: str, ts: str, nonce: str, body: bytes) -> bytes:
    return f"{method}\n{path}\n{query}\n{ts}\n{nonce}\n{hashlib.sha256(body).hexdigest()}".encode()


def sign(key: bytes, method: str, path: str, query: str, ts: str, nonce: str, body: bytes) -> str:
    return base64.urlsafe_b64encode(hmac.new(key, canonical(method, path, query, ts, nonce, body), hashlib.sha256).digest()).rstrip(b"=").decode()


def carry(queued: list[dict]) -> str | None:
    """The wake's "sphinx" value: every queued blob, oldest first, as compact JSON [{pid, rid, blob}], or None when they
    don't all fit in CARRY_MAX (the wake is a plain "sync" and the phone fetches the inbox, oldest first). Each sealed
    counter must arrive in order: a newer one handled first made the older one a "replay" that was acked away
    (review 2026-10-27), so it is all of them in order or none."""
    out = [{"pid": b["pid"], "rid": b["rid"], "blob": b["blob"]} for b in sorted(queued, key=lambda b: b["at"])]
    s = json.dumps(out, separators=(",", ":"))
    return s if out and len(s) <= CARRY_MAX else None


def fcm_payload(token: str, sphinx: str | None) -> dict:
    """The whole FCM message. Data is exactly {"t": "sync"}, plus "sphinx" when it carries sealed blobs. No title, no
    text: the phone builds its own notification."""
    data = {"t": "sync", **({"sphinx": sphinx} if sphinx else {})}
    return {"message": {"token": token, "data": data, "android": {"priority": "high", "ttl": "60s"}}}


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Fcm:
    """FCM HTTP v1 with a service account file (SPHINX_FCM_ACCOUNT). Absent: available() is False and nothing is sent."""

    def __init__(self, account_path: str | None, audit=None):
        self.path, self.audit = account_path, audit
        self._access = (None, 0.0)
        self._lock = threading.Lock()

    def available(self) -> bool:
        return bool(self.path) and os.path.isfile(self.path)

    def _account(self) -> dict:
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def _bearer(self, sa: dict) -> str:
        with self._lock:
            tok, exp = self._access
            if tok and time.time() < exp - 60:
                return tok
            # Imported here: a relay without FCM never needs it.
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            now = int(time.time())
            head = _b64u(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
            claims = _b64u(json.dumps({"iss": sa["client_email"], "scope": FCM_SCOPE, "aud": sa["token_uri"], "iat": now, "exp": now + 3600}).encode())
            key = serialization.load_pem_private_key(sa["private_key"].encode(), None)
            sig = _b64u(key.sign(f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256()))
            body = f"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={head}.{claims}.{sig}".encode()
            req = urllib.request.Request(sa["token_uri"], body, {"Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=15) as r:
                d = json.loads(r.read())
            self._access = (d["access_token"], time.time() + int(d.get("expires_in", 3600)))
            return self._access[0]

    def send_now(self, token: str, sphinx: str | None) -> int:
        """Blocking. The HTTP status (0: no network)."""
        sa = self._account()
        url = f"https://fcm.googleapis.com/v1/projects/{sa['project_id']}/messages:send"
        req = urllib.request.Request(url, json.dumps(fcm_payload(token, sphinx)).encode(),
                                     {"Authorization": f"Bearer {self._bearer(sa)}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except OSError:
            return 0

    def wake(self, pid: str, token: str, sphinx: str | None) -> None:
        """In the background: the laptop's request call doesn't wait on Google."""
        def go():
            try:
                t0 = time.time()
                code = self.send_now(token, sphinx)
                if self.audit:
                    self.audit(f"wake {code}{' carried' if sphinx else ' NOT carried'} in {time.time() - t0:.2f}s", pid)
            except Exception as e:   # the type only: an FCM error can quote the token
                if self.audit:
                    self.audit(f"wake failed {type(e).__name__}", pid)
        threading.Thread(target=go, daemon=True).start()


class FileStore:
    """The pairings, as one JSON object in a file (written whole, then renamed). None: memory only."""

    def __init__(self, path: str | None):
        self.path, self.data = path, {}
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self.data = json.load(f)

    def get(self) -> dict:
        return dict(self.data)

    def put(self, data: dict) -> None:
        self.data = dict(data)
        if self.path:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f)
            os.replace(tmp, self.path)


def _locked(f):
    """Runs a Relay method under its lock: sync routes (threadpool) and async ones (event loop) share its dicts."""
    @functools.wraps(f)
    def run(self, *a, **k):
        with self.lock:
            return f(self, *a, **k)
    return run


class Relay:
    """Pairings (pid -> relay key, the phone's hello) in the store; blobs in memory, gone after TTL_S."""

    def __init__(self, store: FileStore, clock=time.time, fcm: Fcm | None = None):
        self.s, self.now, self.fcm = store, clock, fcm
        self.inbox: dict[str, list[dict]] = {}       # to the phone, per pairing
        self.replies: dict[tuple[str, str], dict] = {}  # to the laptop, by (pid, rid)
        self.outbox: dict[str, list[dict]] = {}      # handoffs to the laptop, per pairing
        self.files: dict[tuple[str, str], dict] = {}  # (pid, fid) -> {"total", "at", "chunks": {n: ciphertext}}
        self.sent: dict[str, list[float]] = {}
        self.calls: dict[str, list[float]] = {}      # signed calls, per pairing
        self.seen: dict[str, dict[str, float]] = {}  # nonces inside the skew window, per pairing
        self.polls: dict[str, int] = {}              # open long polls, per pairing
        self.phone_at: dict[str, float] = {}         # the phone's last signed call, per pairing, in memory
        self.lock = threading.RLock()

    # ---- pairings ----
    @_locked
    def pairings(self) -> dict:
        return self.s.get()

    @_locked
    def pair(self, pid: str, key: bytes, hello: str) -> None:
        p = self.pairings()
        e = p.get(pid)
        if e is not None:
            # The phone retrying the same registration is fine; anyone else can't take the pid over.
            if hmac.compare_digest(base64.b64decode(e["key"]), key) and e["hello"] == hello:
                return
            raise HTTPException(409, "already paired")
        if len(p) >= MAX_PAIRINGS:
            raise HTTPException(409, f"at most {MAX_PAIRINGS} pairings")
        p[pid] = {"key": base64.b64encode(key).decode(), "hello": hello, "added": int(self.now())}
        self.s.put(p)

    @_locked
    def unpair(self, pid: str) -> bool:
        p = self.pairings()
        gone = p.pop(pid, None) is not None
        if gone:
            self.s.put(p)
        self.inbox.pop(pid, None)
        self.seen.pop(pid, None)
        self.calls.pop(pid, None)
        self.phone_at.pop(pid, None)
        for k in [k for k in self.replies if k[0] == pid]:
            del self.replies[k]
        self.outbox.pop(pid, None)
        for k in [k for k in self.files if k[0] == pid]:
            del self.files[k]
        return gone

    @_locked
    def set_push(self, pid: str, token: str) -> bool:
        """The phone's FCM token for this pairing ("" forgets it). True when a request will now wake it through FCM."""
        p = self.pairings()
        if pid not in p:
            return False
        if token:
            p[pid]["push"] = token
        else:
            p[pid].pop("push", None)
        self.s.put(p)
        return self.can_push(pid)

    @_locked
    def can_push(self, pid: str) -> bool:
        return bool(self.fcm and self.fcm.available() and self.pairings().get(pid, {}).get("push"))

    # ---- the phone's last-seen time, for the laptop's status ----
    @_locked
    def saw_phone(self, pid: str) -> None:
        self.phone_at[pid] = self.now()

    @_locked
    def phone_seen(self, pid: str) -> int | None:
        """When this pairing's phone last made a signed call, rounded down to the minute; None if not since start."""
        t = self.phone_at.get(pid)
        return int(t // SEEN_ROUND_S * SEEN_ROUND_S) if t else None

    @_locked
    def key(self, pid: str) -> bytes | None:
        e = self.pairings().get(pid)
        return base64.b64decode(e["key"]) if e else None

    # ---- the proof ----
    @_locked
    def verify(self, method: str, path: str, query: str, headers, body: bytes) -> str:
        """The pairing id when the HMAC, the time and the nonce are good; else 401 (one message for every reason)."""
        pid, ts, nonce, sig = (headers.get(h) or "" for h in ("x-sphinx-pid", "x-sphinx-ts", "x-sphinx-nonce", "x-sphinx-sig"))
        now = self.now()
        self._sweep(now)
        key = self.key(pid) if PID.match(pid) else None
        good = (key is not None and re.fullmatch(r"\d{1,12}", ts) is not None and abs(now - int(ts)) <= SKEW_S and NONCE.match(nonce) is not None
                and hmac.compare_digest(sig.encode(), sign(key, method, path, query, ts, nonce, body).encode()))
        seen = self.seen.setdefault(pid, {}) if good else {}
        if not good or nonce in seen:
            raise HTTPException(401, "not paired")
        calls = [t for t in self.calls.get(pid, []) if now - t < RATE_S]
        if len(calls) >= CALLS or len(seen) >= NONCES or sum(len(v) for v in self.seen.values()) >= NONCES_ALL:
            raise HTTPException(429, "too many calls")
        self.calls[pid] = calls + [now]
        seen[nonce] = now
        return pid

    @_locked
    def poll_open(self, pid: str) -> None:
        if self.polls.get(pid, 0) >= POLLS or sum(self.polls.values()) >= POLLS_ALL:
            raise HTTPException(429, "too many waiting")
        self.polls[pid] = self.polls.get(pid, 0) + 1

    @_locked
    def poll_done(self, pid: str) -> None:
        n = self.polls.get(pid, 0) - 1
        if n > 0:
            self.polls[pid] = n
        else:
            self.polls.pop(pid, None)

    # ---- blobs ----
    def _sweep(self, now: float) -> None:
        for pid in list(self.inbox):
            self.inbox[pid] = [b for b in self.inbox[pid] if now - b["at"] < TTL_S]
            if not self.inbox[pid]:
                del self.inbox[pid]
        for k in [k for k, v in self.replies.items() if now - v["at"] >= TTL_S]:
            del self.replies[k]
        for pid in list(self.outbox):
            self.outbox[pid] = [b for b in self.outbox[pid] if now - b["at"] < OUT_TTL_S]
            if not self.outbox[pid]:
                del self.outbox[pid]
        for k in [k for k, v in self.files.items() if now - v["at"] >= FILE_TTL_S]:
            del self.files[k]
        for pid in list(self.seen):
            self.seen[pid] = {n: t for n, t in self.seen[pid].items() if now - t <= 2 * SKEW_S}
            if not self.seen[pid]:
                del self.seen[pid]

    # ---- handoff: the laptop's outbox and file chunks ----
    @_locked
    def post_out(self, pid: str, rid: str, blob: str) -> None:
        self._sweep(self.now())
        q = self.outbox.setdefault(pid, [])
        if len(q) >= MAX_QUEUED:
            raise HTTPException(429, "queue full")
        if any(b["rid"] == rid for b in q):
            raise HTTPException(409, "already queued")
        q.append({"rid": rid, "blob": blob, "at": self.now()})

    @_locked
    def take_out(self, pid: str) -> list[dict]:
        """What waits for this pairing's laptop, oldest first. It stays until the laptop acks it (or OUT_TTL_S pass)."""
        self._sweep(self.now())
        return sorted(self.outbox.get(pid, []), key=lambda b: b["at"])

    @_locked
    def ack_out(self, pid: str, rids: list[str]) -> int:
        q = self.outbox.get(pid, [])
        keep = [b for b in q if b["rid"] not in set(rids)]
        if keep:
            self.outbox[pid] = keep
        else:
            self.outbox.pop(pid, None)
        return len(q) - len(keep)

    def _file_bytes(self, pid: str | None = None) -> int:
        return sum(len(c) for k, f in self.files.items() if pid is None or k[0] == pid for c in f["chunks"].values())

    @_locked
    def put_chunk(self, pid: str, fid: str, n: int, total: int, data: bytes) -> None:
        self._sweep(self.now())
        if not (1 <= total <= FILE_CHUNKS and 0 <= n < total) or not (16 < len(data) <= CHUNK_MAX):
            raise HTTPException(400, "bad chunk")
        f = self.files.get((pid, fid))
        if f is None:
            f = self.files[(pid, fid)] = {"total": total, "at": self.now(), "chunks": {}}
        if f["total"] != total:
            raise HTTPException(409, "another file")
        if n in f["chunks"]:
            raise HTTPException(409, "already there")
        if self._file_bytes(pid) + len(data) > PAIR_FILE_BYTES or self._file_bytes() + len(data) > FILE_BYTES_ALL:
            raise HTTPException(507, "file storage full")
        f["chunks"][n] = data

    @_locked
    def get_chunk(self, pid: str, fid: str, n: int) -> bytes | None:
        self._sweep(self.now())
        f = self.files.get((pid, fid))
        return f["chunks"].get(n) if f else None

    @_locked
    def drop_file(self, pid: str, fid: str) -> bool:
        return self.files.pop((pid, fid), None) is not None

    @_locked
    def request(self, pid: str, rid: str, blob: str) -> None:
        now = self.now()
        recent = [t for t in self.sent.get(pid, []) if now - t < RATE_S]
        if len(recent) >= RATE:
            raise HTTPException(429, "too many requests")
        q = self.inbox.setdefault(pid, [])
        if len(q) >= MAX_QUEUED:
            raise HTTPException(429, "queue full")
        if any(b["rid"] == rid for b in q):
            raise HTTPException(409, "already queued")
        self.sent[pid] = recent + [now]
        q.append({"rid": rid, "blob": blob, "at": now})
        token = self.pairings().get(pid, {}).get("push")
        if token and self.fcm and self.fcm.available():
            self.fcm.wake(pid, token, carry([{**b, "pid": pid} for b in q]))

    @_locked
    def take(self, pid: str) -> list[dict] | None:
        """What waits for this pairing's phone, oldest first, or None. It stays until acked (or expired), so a phone
        that dies mid-way gets it again; the sealed counter stops it from being acted on twice."""
        self._sweep(self.now())
        q = self.inbox.get(pid)
        return sorted(q, key=lambda b: b["at"]) if q else None

    @_locked
    def ack(self, pid: str, rids: list[str]) -> int:
        q = self.inbox.get(pid, [])
        keep = [b for b in q if b["rid"] not in set(rids)]
        if keep:
            self.inbox[pid] = keep
        else:
            self.inbox.pop(pid, None)
        return len(q) - len(keep)

    @_locked
    def reply(self, pid: str, rid: str, blob: str) -> None:
        self._sweep(self.now())
        if sum(1 for k in self.replies if k[0] == pid) >= MAX_QUEUED:
            raise HTTPException(429, "queue full")
        self.replies[(pid, rid)] = {"blob": blob, "at": self.now()}

    @_locked
    def pop_reply(self, pid: str, rid: str) -> str | None:
        self._sweep(self.now())
        r = self.replies.pop((pid, rid), None)
        return r["blob"] if r else None


class PairBody(BaseModel):
    pid: str = Field(pattern=PID.pattern)
    key: str = Field(min_length=43, max_length=44)     # 32 bytes, b64url
    hello: str = Field(min_length=24, max_length=600)  # the phone's public key and its proof, b64url; the laptop checks it


class BlobBody(BaseModel):
    rid: str = Field(pattern=RID.pattern)
    blob: str = Field(pattern=BLOB.pattern)


class PushBody(BaseModel):
    token: str = Field(max_length=512)


class ChunkBody(BaseModel):
    blob: str = Field(min_length=24, max_length=FILE_BODY_MAX)


class AckBody(BaseModel):
    rids: list[str] = Field(max_length=200)


def _blob_ok(blob: str) -> None:
    try:
        if len(_b64d(blob)) > MAX_BLOB:
            raise HTTPException(413, "too large")
    except (binascii.Error, ValueError):
        raise HTTPException(400, "bad blob")


async def _wait(get):
    """Long poll: the value as soon as there is one, else None after WAIT_S."""
    end = time.monotonic() + WAIT_S
    while True:
        v = get()
        if v is not None or time.monotonic() >= end:
            return v
        await asyncio.sleep(0.25)


def audit(what: str, pid: str) -> None:
    # TIMING (2026-10-27): warning level so the journal shows it with its time.
    log.warning("TIMING %.3f %s %s", time.time(), what, pid[:6])


# ---- the app's self-update: a release the owner puts in SPHINX_APP_DIR, served to any pairing ----
# The owner signs the APK and writes app.json next to it on the VPS; the relay only reads, fresh on every call, so the
# release can be replaced while it runs. The phone checks the sha256 against the bytes before installing.
APK_NAME = r"^[A-Za-z0-9._-]{1,100}\.apk$"       # a plain file name in the folder, never a path


class AppRelease(BaseModel):
    versionCode: int = Field(gt=0)
    versionName: str = Field(min_length=1, max_length=40)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=1, le=100_000_000)
    file: str = Field(pattern=APK_NAME)
    notes: str | None = Field(default=None, max_length=2000)


_app_refused: str | None = None   # why the last read found no release, so it is logged once and not on every call


def app_release(folder: str | None) -> tuple[AppRelease, str] | None:
    """The release in [folder]: app.json validated, and the path of the APK it names, when that file is there with the
    stated size. None (the routes say 404) without a folder or an app.json; also for a json that fails AppRelease or an
    APK that is missing or another size, logged once by its reason (never the json's text)."""
    global _app_refused
    if not folder or not os.path.isfile(os.path.join(folder, "app.json")):
        return None
    try:
        with open(os.path.join(folder, "app.json"), encoding="utf-8") as f:
            rel = AppRelease.model_validate_json(f.read())
        path = os.path.join(folder, rel.file)
        if not os.path.isfile(path) or os.path.getsize(path) != rel.size:
            raise FileNotFoundError("the named APK, at the stated size")
    except (OSError, ValueError) as e:
        reason = f"{type(e).__name__}: {e}" if isinstance(e, FileNotFoundError) else type(e).__name__
        if reason != _app_refused:
            _app_refused = reason
            audit(f"app release refused ({reason})", "")
        return None
    _app_refused = None
    return rel, path


# ---- the encrypted backup (docs/DESIGN.md, "Backup") ----
# One user's relay: a slot "pass" (the backup passcode's) and at most one recovery-phrase slot, each holding a verifier
# (SHA-256 of an auth value the phone derives from the passcode or the phrase), the passcode's public Argon2id salt and
# parameters, and one opaque ciphertext the relay can't open. Restore = the auth value, checked here, then the blob.
SLOT = re.compile(r"^(pass|[A-Za-z0-9_-]{43})$")
AUTH = re.compile(r"^[A-Za-z0-9_-]{43}$")          # 32 bytes, b64url
BACKUP_BLOB_MAX = 8_000_000                        # chars of b64url: a 4 MB Keys safe and the accounts, with room to spare
BACKUP_BODY_MAX = BACKUP_BLOB_MAX + 4_096
# The attempt guard. A wrong auth on any backup route is a guess at that slot's secret. These limits are what stands
# between an online attacker and the passcode: each client IP gets PER_IP_FREE free tries, then waits 30 s doubling per
# failure (up to a day); all IPs together get GLOBAL_FREE per slot, then a minute doubling; after GLOBAL_LOCK failures
# in a row that slot is locked until someone with the VPS removes its lock file (`rm <SPHINX_BACKUP_DIR>/backup.<slot>.locked`;
# a `backup.locked` from before locks every slot). Per slot (review 2026-10-27): guesses at one slot can't lock another.
# A right answer resets that IP's and that slot's count. Counts survive a restart (backup-guard.json). Every backup route
# needs the relay's registration token or a paired phone's signature first, so a stranger can't even make a guess.
# Offline, someone holding the VPS's backup file is limited only by the passcode's strength and Argon2id's cost
# (docs/DESIGN.md says so).
PER_IP_FREE, PER_IP_WAIT_S = 3, 30
GLOBAL_FREE, GLOBAL_WAIT_S = 10, 60
GLOBAL_LOCK = 25
# A pairing-signed caller (review 2026-10-27): its own count, apart from the slot's, and after PAIRING_LOCK misses in all
# that pairing may not try again (persisted; the relay holds at most MAX_PAIRINGS), so online guesses stay bounded.
PAIRING_LOCK = 10
WAIT_MAX_S = 24 * 3600


class Backup:
    """The backup slots (backup.json) and the attempt guard (backup-guard.json, backup.locked), all in [folder]."""

    def __init__(self, folder: str | None, clock=time.time):
        self.dir, self.now, self.lock = folder, clock, threading.RLock()
        self.slots: dict = self._read("backup.json") or {}
        g = self._read("backup-guard.json") or {}
        self.ips: dict = g.get("ips", {})
        # Each slot's count; a file from before per-slot counts held one global count, the passcode's.
        self.guard: dict = g.get("slots") or ({"pass": g["global"]} if g.get("global") else {})
        # Each pairing-signed caller's misses in all ("pairing:<pid>" -> n), never evicted.
        self.callers: dict = g.get("pairings", {})

    def _path(self, name: str) -> str | None:
        return os.path.join(self.dir, name) if self.dir else None

    def _read(self, name: str):
        p = self._path(name)
        if p and os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)
        return None

    def _write(self, name: str, data) -> None:
        p = self._path(name)
        if p:
            with open(p + ".tmp", "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(p + ".tmp", p)

    def count(self, slot: str) -> dict:
        return self.guard.get(slot, {"n": 0, "at": 0})

    def _lock_file(self, slot: str) -> str | None:
        return self._path(f"backup.{slot}.locked")

    def locked(self, slot: str) -> bool:
        legacy, p = self._path("backup.locked"), self._lock_file(slot)
        if (legacy and os.path.exists(legacy)) or (p and os.path.exists(p)):
            return True
        if self.count(slot)["n"] >= GLOBAL_LOCK and p:
            # The lock file was removed on the VPS: that is the reset.
            self.guard.pop(slot, None)
            self._save_guard()
        return not p and self.count(slot)["n"] >= GLOBAL_LOCK

    def _save_guard(self) -> None:
        self._write("backup-guard.json", {"ips": self.ips, "slots": self.guard, "pairings": self.callers})

    @staticmethod
    def _wait(n: int, free: int, base: int) -> int:
        return 0 if n < free else min(WAIT_MAX_S, base * 2 ** (n - free))

    def check(self, ip: str, slot: str, shared: bool = True) -> None:
        """Before a guess: 423 when the slot is locked, 429 (with Retry-After) while this IP or everyone must wait for it.
        [shared] False (a pairing-signed caller): only its own count applies, not the slot's."""
        with self.lock:
            if self.locked(slot):
                raise HTTPException(423, "backup locked: reset on the VPS")
            if not shared and self.callers.get(ip, 0) >= PAIRING_LOCK:
                raise HTTPException(423, "this pairing may not try again: reset on the VPS")
            now = self.now()
            e, g = self.ips.get(ip, {"n": 0, "at": 0}), (self.count(slot) if shared else {"n": 0, "at": 0})
            left = max(e["at"] + self._wait(e["n"], PER_IP_FREE, PER_IP_WAIT_S) - now,
                       g["at"] + self._wait(g["n"], GLOBAL_FREE, GLOBAL_WAIT_S) - now)
            if left > 0:
                raise HTTPException(429, "too many wrong tries: wait", headers={"Retry-After": str(int(left) + 1)})

    def failed(self, ip: str, slot: str, shared: bool = True) -> None:
        with self.lock:
            now = self.now()
            e = self.ips.get(ip, {"n": 0, "at": 0})
            self.ips[ip] = {"n": e["n"] + 1, "at": now}
            if len(self.ips) > 1000:   # bounded: the oldest IP entries go, the global count stays
                for k in sorted(self.ips, key=lambda k: self.ips[k]["at"])[:100]:
                    del self.ips[k]
            if not shared:
                # A pairing-signed caller's misses count against it alone, never toward the slot's lock (review
                # 2026-10-27: any pairing, the Signer's too, could otherwise burn the owner's guesses), and lock it
                # for good at PAIRING_LOCK.
                self.callers[ip] = self.callers.get(ip, 0) + 1
                self._save_guard()
                return
            g = {"n": self.count(slot)["n"] + 1, "at": now}
            self.guard[slot] = g
            if g["n"] >= GLOBAL_LOCK and self._lock_file(slot):
                with open(self._lock_file(slot), "w", encoding="utf-8") as fh:
                    fh.write(f"locked after {g['n']} wrong tries at {int(now)}; remove this file to unlock\n")
            self._save_guard()

    def ok(self, ip: str, slot: str) -> None:
        # A success clears that slot's count only: one on another slot (a phrase slot) never resets the guesses against
        # the passcode (review 2026-10-26).
        with self.lock:
            self.ips.pop(ip, None)
            self.guard.pop(slot, None)
            self._save_guard()

    def _match(self, slot: str, auth: str) -> bool:
        e = self.slots.get(slot)
        return e is not None and hmac.compare_digest(e["verifier"], hashlib.sha256(auth.encode()).hexdigest())

    def guarded(self, ip: str, slot: str, auth: str, shared: bool = True) -> dict:
        """The slot when [auth] is its auth value; every miss is a counted guess (404 and 401 alike)."""
        self.check(ip, slot, shared)
        with self.lock:
            if not self._match(slot, auth):
                self.failed(ip, slot, shared)
                raise HTTPException(401, "wrong passcode or phrase")
            self.ok(ip, slot)
            return self.slots[slot]

    def put(self, slot: str, entry: dict) -> None:
        with self.lock:
            others = [k for k in self.slots if k != slot and k != "pass"]
            if slot != "pass" and others:
                raise HTTPException(409, "one recovery phrase at a time: remove the old one first")
            self.slots[slot] = entry
            self._write("backup.json", self.slots)

    def drop(self, slot: str) -> None:
        with self.lock:
            self.slots.pop(slot, None)
            self._write("backup.json", self.slots)


class BackupPut(BaseModel):
    auth: str = Field(pattern=AUTH.pattern)
    new_auth: str | None = Field(default=None, pattern=AUTH.pattern)
    salt: str | None = Field(default=None, max_length=64)
    kdf: dict | None = None
    blob: str = Field(min_length=24, max_length=BACKUP_BLOB_MAX)
    # False: update only, a slot that is gone stays gone (404). The phone's routine uploads send false, so a stale copy
    # of its settings can't bring a removed slot (a recovery phrase turned off) back (review 2026-10-27).
    create: bool = True


class BackupAuth(BaseModel):
    auth: str = Field(pattern=AUTH.pattern)


def client_ip(request: Request) -> str:
    """The caller's address. Behind Caddy on the unix socket there is no peer address, so Caddy's X-Forwarded-For is
    used (Caddy sets it itself; it trusts no incoming one, having no trusted_proxies); a TCP peer is used as it is."""
    peer = request.client.host if request.client else ""
    if not peer or peer in ("127.0.0.1", "::1"):
        fwd = request.headers.get("x-forwarded-for", "").split(",")[-1].strip()
        return fwd[:64] or peer or "unknown"
    return peer


def create_app(relay: Relay | None = None, register_token: str | None = None, backup: Backup | None = None,
               insecure_dev: bool | None = None, app_dir: str | None = None) -> FastAPI:
    token = os.environ.get("SPHINX_REGISTER_TOKEN", "") if register_token is None else register_token
    insecure = os.environ.get("SPHINX_INSECURE_DEV") == "1" if insecure_dev is None else insecure_dev
    app_dir = (os.environ.get("SPHINX_APP_DIR") or None) if app_dir is None else app_dir
    # Fail closed (review 2026-10-27): without a registration token anyone could register pairings and reach the backup
    # routes. Only an explicit SPHINX_INSECURE_DEV=1 (local testing) runs it open.
    if not token and not insecure:
        raise RuntimeError("SPHINX_REGISTER_TOKEN is not set: the relay won't run open. Set it (deploy/install.sh does), "
                           "or SPHINX_INSECURE_DEV=1 for local testing only.")
    relay = relay or Relay(FileStore(os.environ.get("SPHINX_STATE", "sphinx-relay.json")),
                           fcm=Fcm(os.environ.get("SPHINX_FCM_ACCOUNT") or None, audit))
    backup = backup or Backup(os.environ.get("SPHINX_BACKUP_DIR") or os.path.dirname(os.path.abspath(os.environ.get("SPHINX_STATE", "sphinx-relay.json"))))
    app = FastAPI(title="Sphinx relay", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.relay = relay

    async def signed(request: Request, limit: int = 2 * MAX_BLOB) -> tuple[str, bytes]:
        if int(request.headers.get("content-length") or 0) > limit:
            raise HTTPException(413, "too large")
        body = await request.body()
        if len(body) > limit:
            raise HTTPException(413, "too large")
        pid = relay.verify(request.method, request.url.path, request.url.query, request.headers, body)
        return pid, body

    async def phone(request: Request) -> tuple[str, bytes]:
        """A signed call on one of the phone's routes: also the time the laptop's status shows."""
        pid, body = await signed(request)
        relay.saw_phone(pid)
        return pid, body

    def parse(model, body: bytes):
        try:
            return model.model_validate_json(body)
        except ValueError:
            raise HTTPException(400, "bad request")

    async def long_poll(pid: str, get):
        relay.poll_open(pid)
        try:
            return await _wait(get)
        finally:
            relay.poll_done(pid)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    # ---- the phone ----
    @app.post("/v1/pairings")
    def pair(b: PairBody, request: Request):
        if token and not hmac.compare_digest(request.headers.get("x-sphinx-token", "").encode(), token.encode()):
            raise HTTPException(403, "registration token required")
        try:
            key = _b64d(b.key)
        except (binascii.Error, ValueError):
            raise HTTPException(400, "bad key")
        if len(key) != 32:
            raise HTTPException(400, "bad key")
        relay.pair(b.pid, key, b.hello)
        audit("pair", b.pid)
        return {"ok": True}

    @app.delete("/v1/pairings/{pid}")
    async def unpair(pid: str, request: Request):
        who, _ = await phone(request)
        if who != pid:
            raise HTTPException(403, "another pairing")
        audit("unpair", pid)
        return {"ok": relay.unpair(pid)}

    @app.get("/v1/inbox")
    async def inbox(request: Request):
        # What is queued now, never a long poll: the phone holds no live connection. It fetches after an FCM wake, when
        # the app comes to the front, and on its heartbeat. (The old "?wait=0" is accepted and changes nothing.)
        pid, _ = await phone(request)
        items = relay.take(pid)
        audit(f"inbox fetched {len(items or [])}", pid)
        return {"items": [{"rid": b["rid"], "blob": b["blob"]} for b in items or []]}

    @app.post("/v1/inbox/ack")
    async def inbox_ack(request: Request):
        pid, body = await phone(request)
        audit("inbox ack", pid)
        return {"acked": relay.ack(pid, parse(AckBody, body).rids)}

    @app.post("/v1/push")
    async def push(request: Request):
        # The phone's FCM token for this pairing; the answer says whether requests will now wake it through FCM (else
        # the phone keeps its long poll).
        pid, body = await phone(request)
        t = parse(PushBody, body).token
        if t and not PUSH_TOKEN.match(t):
            raise HTTPException(400, "bad token")
        on = relay.set_push(pid, t)
        audit("push on" if on else "push off", pid)
        return {"push": on}

    @app.post("/v1/replies")
    async def reply(request: Request):
        pid, body = await phone(request)
        b = parse(BlobBody, body)
        _blob_ok(b.blob)
        relay.reply(pid, b.rid, b.blob)
        audit("reply stored", pid)
        return {"ok": True}

    # ---- the laptop ----
    @app.get("/v1/hello")
    async def hello(request: Request):
        pid, _ = await signed(request)
        return {"hello": relay.pairings().get(pid, {}).get("hello")}

    # ---- handoff (either end): the laptop's outbox, and file chunks ----
    @app.post("/v1/outbox")
    async def outbox_post(request: Request):
        # A sealed handoff from the phone for the laptop (direction 'p', its own counter). Nothing here is readable.
        pid, body = await phone(request)
        b = parse(BlobBody, body)
        _blob_ok(b.blob)
        relay.post_out(pid, b.rid, b.blob)
        audit("handoff", pid)
        return {"queued": True}

    @app.get("/v1/outbox")
    async def outbox_get(request: Request):
        pid, _ = await signed(request)
        return {"items": [{"rid": b["rid"], "blob": b["blob"]} for b in relay.take_out(pid)]}

    @app.post("/v1/outbox/ack")
    async def outbox_ack(request: Request):
        pid, body = await signed(request)
        return {"acked": relay.ack_out(pid, parse(AckBody, body).rids)}

    def _file_args(fid: str, n: int | None = None):
        if not FID.match(fid) or (n is not None and not 0 <= n < FILE_CHUNKS):
            raise HTTPException(400, "bad file")

    @app.put("/v1/files/{fid}/{n}")
    async def chunk_put(fid: str, n: int, request: Request, of: int = 0):
        pid, body = await signed(request, limit=FILE_BODY_MAX)
        _file_args(fid, n)
        b = parse(ChunkBody, body)
        try:
            data = _b64d(b.blob)
        except (binascii.Error, ValueError):
            raise HTTPException(400, "bad chunk")
        relay.put_chunk(pid, fid, n, of, data)
        return {"ok": True}

    @app.get("/v1/files/{fid}/{n}")
    async def chunk_get(fid: str, n: int, request: Request):
        pid, _ = await signed(request)
        _file_args(fid, n)
        data = relay.get_chunk(pid, fid, n)
        if data is None:
            raise HTTPException(404, "no such chunk")
        return {"blob": base64.urlsafe_b64encode(data).rstrip(b"=").decode()}

    @app.delete("/v1/files/{fid}")
    async def file_drop(fid: str, request: Request):
        pid, _ = await signed(request)
        _file_args(fid)
        return {"ok": relay.drop_file(pid, fid)}

    # ---- the backup: no pairing needed (a new phone has none), guarded by the attempt limits above ----
    def slot_ok(slot: str) -> None:
        if not SLOT.match(slot):
            raise HTTPException(400, "bad slot")

    def caller_ok(request: Request, body: bytes) -> tuple[str, bool]:
        """Every backup route: the relay's registration token, or a paired phone's signature (review 2026-10-27:
        unauthenticated, anyone could make guesses and lock the backup). Not a counted guess. Only a relay started with
        SPHINX_INSECURE_DEV=1 has no token, and then every caller passes as a token holder.
        Returns who counts the guesses and whether they count toward the slot: the client IP for a token holder (and on
        a relay without a token); a pairing's own key, apart from the slot's count, for a signed caller."""
        if not token or hmac.compare_digest(request.headers.get("x-sphinx-token", "").encode(), token.encode()):
            return client_ip(request), True
        try:
            pid = relay.verify(request.method, request.url.path, request.url.query, request.headers, body)
        except HTTPException:
            raise HTTPException(403, "registration token or a paired phone's signature required")
        return f"pairing:{pid}", False

    @app.get("/v1/backup/{slot}/salt")
    def backup_salt(slot: str, request: Request):
        # The passcode's public Argon2id salt and cost, so a new phone can derive its auth value. Counted like a try
        # (it is the first step of one), so the slots can't be probed for free.
        slot_ok(slot)
        who, shared = caller_ok(request, b"")
        backup.check(who, slot, shared)
        e = backup.slots.get(slot)
        if e is None or not e.get("salt"):
            backup.failed(who, slot, shared)
            raise HTTPException(404, "no backup here")
        return {"salt": e["salt"], "kdf": e.get("kdf")}

    @app.post("/v1/backup/{slot}/open")
    async def backup_open(slot: str, request: Request):
        slot_ok(slot)
        body = await request.body()
        who, shared = caller_ok(request, body)
        b = parse(BackupAuth, body)
        e = backup.guarded(who, slot, b.auth, shared)
        audit("backup opened", slot)
        return {"blob": e["blob"], "at": e.get("at")}

    @app.put("/v1/backup/{slot}")
    async def backup_put(slot: str, request: Request):
        # Update: the slot's own auth value (a counted guess when wrong). Create: the relay's registration token when it
        # has one, as for pairing, so a stranger can't take an empty relay's slot first.
        slot_ok(slot)
        if int(request.headers.get("content-length") or 0) > BACKUP_BODY_MAX:
            raise HTTPException(413, "too large")
        body = await request.body()
        if len(body) > BACKUP_BODY_MAX:
            raise HTTPException(413, "too large")
        who, shared = caller_ok(request, body)
        b = parse(BackupPut, body)
        if slot in backup.slots:
            backup.guarded(who, slot, b.auth, shared)
        elif not b.create:
            raise HTTPException(404, "no backup here")
        elif not shared:
            # Creating a slot takes the registration token itself: a pairing (the Signer's, say) can't plant a phrase slot.
            raise HTTPException(403, "creating a backup slot needs the registration token")
        if slot == "pass" and not b.salt:
            raise HTTPException(400, "the passcode slot needs its salt")
        backup.put(slot, {"verifier": hashlib.sha256((b.new_auth or b.auth).encode()).hexdigest(), "salt": b.salt, "kdf": b.kdf,
                          "blob": b.blob, "at": int(backup.now())})
        audit("backup stored", slot)
        return {"ok": True}

    @app.post("/v1/backup/{slot}/delete")
    async def backup_delete(slot: str, request: Request):
        slot_ok(slot)
        body = await request.body()
        who, shared = caller_ok(request, body)
        b = parse(BackupAuth, body)
        backup.guarded(who, slot, b.auth, shared)
        backup.drop(slot)
        audit("backup removed", slot)
        return {"ok": True}

    # ---- the app's self-update (either end may ask; the phone installs, the laptop may show the version) ----
    @app.get("/v1/app")
    async def app_get(request: Request):
        pid, _ = await signed(request)
        r = app_release(app_dir)
        if r is None:
            raise HTTPException(404, "no release")
        audit("app checked", pid)
        return r[0].model_dump()

    @app.get("/v1/app/file")
    async def app_file(request: Request):
        # The APK itself, read from the folder now (the owner may have replaced it); the json's sha256 rides in a
        # header so the phone can refuse bytes that don't match it.
        pid, _ = await signed(request)
        r = app_release(app_dir)
        if r is None:
            raise HTTPException(404, "no release")
        audit("app sent", pid)
        return FileResponse(r[1], media_type="application/vnd.android.package-archive", headers={"x-sphinx-sha256": r[0].sha256})

    @app.get("/v1/status")
    async def status(request: Request):
        # The extension's icon: paired (this call verified) and when this pairing's phone last made a signed call, to
        # the minute. Nothing about the phone but that; nothing is woken.
        pid, _ = await signed(request)
        return {"paired": True, "phone_seen": relay.phone_seen(pid), "push": relay.can_push(pid), "now": int(relay.now())}

    @app.post("/v1/requests")
    async def send(request: Request):
        pid, body = await signed(request)
        b = parse(BlobBody, body)
        _blob_ok(b.blob)
        relay.request(pid, b.rid, b.blob)
        audit("request", pid)
        return {"queued": True}

    @app.get("/v1/replies/{rid}")
    async def replies(rid: str, request: Request):
        pid, _ = await signed(request)
        if not RID.match(rid):
            raise HTTPException(400, "bad request id")
        audit("reply poll start", pid)
        blob = await long_poll(pid, lambda: relay.pop_reply(pid, rid))
        audit(f"reply poll end {'got' if blob else 'empty'}", pid)
        return {"blob": blob} if blob else Response(status_code=204)

    return app


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(create_app(), host=os.environ.get("SPHINX_HOST", "127.0.0.1"), port=int(os.environ.get("SPHINX_PORT", "8080")),
                proxy_headers=True, forwarded_allow_ips=os.environ.get("SPHINX_TRUSTED_PROXIES", "127.0.0.1"))
