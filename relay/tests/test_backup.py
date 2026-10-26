"""The encrypted backup's slots and the attempt guard that stands in for an email code."""
import hashlib
import os
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import sphinx_relay as hr
from test_relay import b64

AUTH, OTHER = b64(b"a" * 32), b64(b"b" * 32)
PHRASE = b64(b"p" * 32)
BLOB = b64(b"sealed state " * 10)


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def backup(tmp_path, clock):
    return hr.Backup(str(tmp_path), clock)


@pytest.fixture
def client(backup):
    return TestClient(hr.create_app(hr.Relay(hr.FileStore(None)), register_token="tok", backup=backup))


def put(client, slot="pass", auth=AUTH, blob=BLOB, token="tok", **kw):
    body = {"auth": auth, "blob": blob, **({"salt": b64(b"s" * 16), "kdf": {"m": 65536, "t": 3, "p": 1}} if slot == "pass" else {}), **kw}
    return client.put(f"/v1/backup/{slot}", json=body, headers={"x-sphinx-token": token} if token else {})


def test_store_then_restore_with_the_passcodes_auth(client, backup):
    assert put(client).json() == {"ok": True}
    assert client.get("/v1/backup/pass/salt").json() == {"salt": b64(b"s" * 16), "kdf": {"m": 65536, "t": 3, "p": 1}}
    assert client.post("/v1/backup/pass/open", json={"auth": AUTH}).json()["blob"] == BLOB
    # The relay keeps a verifier, never the auth value itself.
    assert backup.slots["pass"]["verifier"] == hashlib.sha256(AUTH.encode()).hexdigest()
    assert AUTH not in open(os.path.join(backup.dir, "backup.json")).read()


def test_creating_needs_the_relay_token_and_updating_needs_the_auth(client):
    assert put(client, token="").status_code == 403
    assert put(client, token="wrong").status_code == 403
    assert put(client).status_code == 200
    assert put(client, auth=OTHER, blob=b64(b"evil" * 10)).status_code == 401      # someone else's update: a counted guess
    assert put(client, blob=b64(b"newer" * 10), token="").status_code == 200        # the owner needs no token to update
    # Changing the passcode: the old auth, then the new one.
    assert put(client, new_auth=OTHER, blob=b64(b"newer" * 10), token="").status_code == 200
    assert client.post("/v1/backup/pass/open", json={"auth": AUTH}).status_code == 401
    assert client.post("/v1/backup/pass/open", json={"auth": OTHER}).json()["blob"] == b64(b"newer" * 10)


def test_wrong_tries_back_off_per_ip_then_globally_then_lock_until_the_vps_resets(backup, clock):
    backup.put("pass", {"verifier": hashlib.sha256(AUTH.encode()).hexdigest(), "salt": "s", "blob": BLOB})
    for _ in range(hr.PER_IP_FREE):
        with pytest.raises(hr.HTTPException) as e:
            backup.guarded("1.1.1.1", "pass", OTHER)
        assert e.value.status_code == 401
    # Now this IP waits, even with the right answer.
    with pytest.raises(hr.HTTPException) as e:
        backup.guarded("1.1.1.1", "pass", AUTH)
    assert e.value.status_code == 429 and int(e.value.headers["Retry-After"]) == hr.PER_IP_WAIT_S + 1
    clock.t += hr.PER_IP_WAIT_S
    assert backup.guarded("1.1.1.1", "pass", AUTH)["blob"] == BLOB             # a right answer resets the count
    # Spread over many IPs, the global count catches up: backoff, then a lock.
    ips = (f"10.0.0.{i}" for i in range(1000))
    for _ in range(hr.GLOBAL_FREE):
        with pytest.raises(hr.HTTPException):
            backup.guarded(next(ips), "pass", OTHER)
    with pytest.raises(hr.HTTPException) as e:
        backup.guarded(next(ips), "pass", OTHER)
    assert e.value.status_code == 429
    while backup.glob["n"] < hr.GLOBAL_LOCK:
        clock.t += hr.WAIT_MAX_S
        with pytest.raises(hr.HTTPException):
            backup.guarded(next(ips), "pass", OTHER)
    clock.t += hr.WAIT_MAX_S
    with pytest.raises(hr.HTTPException) as e:
        backup.guarded("1.1.1.1", "pass", AUTH)
    assert e.value.status_code == 423                                         # even the right answer: locked
    assert os.path.exists(os.path.join(backup.dir, "backup.locked"))
    # The counts survive a restart.
    again = hr.Backup(backup.dir, clock)
    with pytest.raises(hr.HTTPException) as e:
        again.guarded("1.1.1.1", "pass", AUTH)
    assert e.value.status_code == 423
    # Removing the lock file on the VPS is the reset.
    os.remove(os.path.join(backup.dir, "backup.locked"))
    assert again.guarded("1.1.1.1", "pass", AUTH)["blob"] == BLOB


def test_the_salt_route_and_unknown_slots_count_as_tries(client, backup):
    for _ in range(hr.PER_IP_FREE):
        assert client.get("/v1/backup/pass/salt").status_code == 404
    assert client.get("/v1/backup/pass/salt").status_code == 429
    assert client.post("/v1/backup/bad!/open", json={"auth": AUTH}).status_code == 400


def test_one_recovery_phrase_slot_beside_the_passcode_and_removal_needs_its_auth(client, backup):
    assert put(client).status_code == 200
    assert put(client, slot=PHRASE, auth=OTHER).status_code == 200
    assert put(client, slot=b64(b"q" * 32), auth=OTHER).status_code == 409   # one phrase at a time
    assert client.post(f"/v1/backup/{PHRASE}/open", json={"auth": OTHER}).json()["blob"] == BLOB
    assert client.post(f"/v1/backup/{PHRASE}/delete", json={"auth": AUTH}).status_code == 401
    assert client.post(f"/v1/backup/{PHRASE}/delete", json={"auth": OTHER}).json() == {"ok": True}
    assert set(backup.slots) == {"pass"}
    assert put(client, slot=b64(b"q" * 32), auth=OTHER).status_code == 200   # now a new phrase may come


def test_size_caps(client):
    assert put(client, blob="x" * (hr.BACKUP_BLOB_MAX + 1)).status_code in (400, 413)
    assert client.put("/v1/backup/pass", content=b"x" * (hr.BACKUP_BODY_MAX + 10), headers={"x-sphinx-token": "tok"}).status_code == 413


def test_the_client_ip_behind_caddys_socket_is_its_forwarded_for():
    req = lambda peer, fwd: SimpleNamespace(client=SimpleNamespace(host=peer) if peer else None, headers={"x-forwarded-for": fwd} if fwd else {})
    assert hr.client_ip(req(None, "203.0.113.9")) == "203.0.113.9"
    assert hr.client_ip(req("127.0.0.1", "198.51.100.1, 203.0.113.9")) == "203.0.113.9"
    # A direct TCP caller can't pick its own address with the header.
    assert hr.client_ip(req("192.0.2.7", "203.0.113.9")) == "192.0.2.7"


def test_a_success_on_another_slot_never_resets_the_passcode_guesses(backup, clock):
    # Review 2026-10-26: a phrase slot made with the laptop's registration token must not clear the global count.
    backup.put("pass", {"verifier": hashlib.sha256(AUTH.encode()).hexdigest(), "salt": "s", "blob": BLOB})
    backup.put(PHRASE, {"verifier": hashlib.sha256(PHRASE.encode()).hexdigest(), "salt": "", "blob": BLOB})
    ips = (f"10.0.1.{i}" for i in range(1000))
    for _ in range(hr.GLOBAL_FREE):
        backup.guarded("9.9.9.9", PHRASE, PHRASE)                               # its own slot, between guesses
        with pytest.raises(hr.HTTPException):
            backup.guarded(next(ips), "pass", OTHER)
    assert backup.glob["n"] == hr.GLOBAL_FREE
    with pytest.raises(hr.HTTPException) as e:
        backup.guarded(next(ips), "pass", OTHER)
    assert e.value.status_code == 429
