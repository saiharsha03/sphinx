import base64
import json
import secrets
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import sphinx_relay as hr

KEY = bytes(range(32))
PID = base64.urlsafe_b64encode(b"p" * 16).rstrip(b"=").decode()
HELLO = "h" * 80
VECTORS = Path(__file__).resolve().parents[2] / "extension" / "test" / "vectors.json"


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@pytest.fixture
def relay(monkeypatch):
    monkeypatch.setattr(hr, "WAIT_S", 0.3)
    return hr.Relay(hr.FileStore(None))


@pytest.fixture
def client(relay):
    c = TestClient(hr.create_app(relay, register_token="", insecure_dev=True))
    assert c.post("/v1/pairings", json={"pid": PID, "key": b64(KEY), "hello": HELLO}).status_code == 200
    return c


def call(client, method, path, body=b"", key=KEY, pid=PID, ts=None, nonce=None, query=""):
    ts = str(int(time.time()) if ts is None else ts)
    nonce = nonce or secrets.token_urlsafe(16)
    h = {"x-sphinx-pid": pid, "x-sphinx-ts": ts, "x-sphinx-nonce": nonce, "content-type": "application/json",
         "x-sphinx-sig": hr.sign(key, method, path, query, ts, nonce, body)}
    return client.request(method, path + ("?" + query if query else ""), content=body or None, headers=h)


def ask(client, rid="r" * 22, blob=None, **kw):
    return call(client, "POST", "/v1/requests", json.dumps({"rid": rid, "blob": blob or b64(b"s" * 64)}).encode(), **kw)


def j(o):
    return json.dumps(o).encode()


def test_a_request_reaches_the_phone_and_the_reply_comes_back(client):
    assert ask(client).status_code == 200
    got = call(client, "GET", "/v1/inbox").json()["items"]
    assert [b["rid"] for b in got] == ["r" * 22]
    # It stays until the phone acks it after handling; then it is gone (the next poll waits, then comes back empty).
    assert len(call(client, "GET", "/v1/inbox").json()["items"]) == 1
    assert call(client, "POST", "/v1/inbox/ack", j({"rids": ["r" * 22]})).json() == {"acked": 1}
    assert call(client, "GET", "/v1/inbox").json() == {"items": []}
    assert call(client, "POST", "/v1/replies", j({"rid": "r" * 22, "blob": b64(b"c" * 40)})).status_code == 200
    r = call(client, "GET", f"/v1/replies/{'r' * 22}")
    assert r.status_code == 200 and r.json()["blob"] == b64(b"c" * 40)
    assert call(client, "GET", f"/v1/replies/{'r' * 22}").status_code == 204  # gone after one read


def test_the_hello_is_what_the_phone_registered(client):
    assert call(client, "GET", "/v1/hello").json() == {"hello": HELLO}


def test_a_registered_pairing_cant_be_taken_over(client):
    # The phone retrying its own registration is fine.
    assert client.post("/v1/pairings", json={"pid": PID, "key": b64(KEY), "hello": HELLO}).status_code == 200
    assert client.post("/v1/pairings", json={"pid": PID, "key": b64(b"x" * 32), "hello": HELLO}).status_code == 409
    assert client.post("/v1/pairings", json={"pid": PID, "key": b64(KEY), "hello": "g" * 80}).status_code == 409
    assert call(client, "GET", "/v1/hello").json() == {"hello": HELLO}


def test_the_registration_token_when_the_relay_sets_one(relay):
    c = TestClient(hr.create_app(relay, register_token="tok_123"))
    body = {"pid": PID, "key": b64(KEY), "hello": HELLO}
    assert c.post("/v1/pairings", json=body).status_code == 403
    assert c.post("/v1/pairings", json=body, headers={"x-sphinx-token": "wrong"}).status_code == 403
    assert c.post("/v1/pairings", json=body, headers={"x-sphinx-token": "tok_123"}).status_code == 200


def test_every_other_call_must_be_signed(client):
    assert ask(client, key=b"x" * 32).status_code == 401
    assert ask(client, pid=b64(b"q" * 16)).status_code == 401                    # not paired
    assert ask(client, ts=int(time.time()) - 61).status_code == 401
    assert ask(client, ts=int(time.time()) + 61).status_code == 401
    for method, path in [("GET", "/v1/inbox"), ("POST", "/v1/inbox/ack"), ("POST", "/v1/replies"), ("GET", "/v1/hello"),
                         ("POST", "/v1/requests"), ("GET", f"/v1/replies/{'r' * 22}"), ("DELETE", f"/v1/pairings/{PID}")]:
        assert client.request(method, path).status_code == 401, path
    # A signature covers the body: the same headers on another body fail.
    body = j({"rid": "r" * 22, "blob": b64(b"s" * 64)})
    ts, nonce = str(int(time.time())), secrets.token_urlsafe(16)
    h = {"x-sphinx-pid": PID, "x-sphinx-ts": ts, "x-sphinx-nonce": nonce, "x-sphinx-sig": hr.sign(KEY, "POST", "/v1/requests", "", ts, nonce, body)}
    assert client.post("/v1/requests", content=j({"rid": "t" * 22, "blob": b64(b"s" * 64)}), headers=h).status_code == 401


def test_a_nonce_is_used_once(client):
    assert ask(client, nonce="n" * 20).status_code == 200
    assert ask(client, rid="u" * 22, nonce="n" * 20).status_code == 401


def test_one_pairing_never_reaches_anothers(client, relay):
    other = b64(b"o" * 16)
    assert client.post("/v1/pairings", json={"pid": other, "key": b64(b"k" * 32), "hello": HELLO}).status_code == 200
    assert ask(client).status_code == 200
    assert call(client, "GET", "/v1/inbox", key=b"k" * 32, pid=other).json() == {"items": []}
    assert call(client, "DELETE", f"/v1/pairings/{PID}", key=b"k" * 32, pid=other).status_code == 403
    assert relay.key(PID) == KEY


def test_queue_limits_and_rate(client, relay, monkeypatch):
    monkeypatch.setattr(hr, "RATE", 100)
    for i in range(hr.MAX_QUEUED):
        assert ask(client, rid=f"{i:022d}").status_code == 200
    assert ask(client, rid="z" * 22).status_code == 429                          # 20 queued at most
    assert ask(client, rid=f"{0:022d}").status_code in (409, 429)
    relay.inbox.clear()
    monkeypatch.setattr(hr, "RATE", 3)
    relay.sent.clear()
    for i in range(3):
        assert ask(client, rid=f"a{i:021d}").status_code == 200
    assert ask(client, rid="b" * 22).status_code == 429                          # 3 a minute here


def test_an_unacked_blob_still_expires(client, relay):
    assert ask(client).status_code == 200
    real = relay.now
    relay.now = lambda: real() + hr.TTL_S + 1
    try:
        assert relay.take(PID) is None
    finally:
        relay.now = real


def test_signed_calls_per_pairing_are_capped(client, monkeypatch):
    monkeypatch.setattr(hr, "CALLS", 5)
    for _ in range(5):
        assert call(client, "GET", "/v1/hello").status_code == 200
    assert call(client, "GET", "/v1/hello").status_code == 429                   # any route counts
    assert ask(client).status_code == 429


def test_nonce_storage_is_bounded_per_pairing_and_in_all(client, relay, monkeypatch):
    monkeypatch.setattr(hr, "NONCES", 4)
    for _ in range(4):
        assert call(client, "GET", "/v1/hello").status_code == 200
    assert call(client, "GET", "/v1/hello").status_code == 429                   # refused, not an old nonce evicted
    assert len(relay.seen[PID]) == 4
    monkeypatch.setattr(hr, "NONCES", 100)
    monkeypatch.setattr(hr, "NONCES_ALL", 4)
    assert call(client, "GET", "/v1/hello").status_code == 429
    # Old nonces age out after two skew windows, and the room comes back.
    real = relay.now
    relay.now = lambda: real() + 2 * hr.SKEW_S + 1
    try:
        relay._sweep(relay.now())
        assert PID not in relay.seen
    finally:
        relay.now = real


def test_open_long_polls_are_capped_per_pairing_and_in_all(client, relay, monkeypatch):
    for _ in range(hr.POLLS):
        relay.poll_open(PID)
    with pytest.raises(hr.HTTPException) as e:
        relay.poll_open(PID)
    assert e.value.status_code == 429
    assert call(client, "GET", f"/v1/replies/{'r' * 22}").status_code == 429
    # The phone's inbox is never a long poll, so the cap doesn't stand in its way.
    assert call(client, "GET", "/v1/inbox").status_code == 200
    for _ in range(hr.POLLS):
        relay.poll_done(PID)
    assert PID not in relay.polls
    other = b64(b"o" * 16)
    monkeypatch.setattr(hr, "POLLS_ALL", 2)
    relay.poll_open(other); relay.poll_open(other)
    with pytest.raises(hr.HTTPException):
        relay.poll_open(PID)
    relay.poll_done(other); relay.poll_done(other)
    # A finished poll gives its place back.
    assert call(client, "GET", f"/v1/replies/{'r' * 22}").status_code == 204
    assert relay.polls == {}


def test_replies_expire_after_60_seconds(client, relay):
    real = relay.now
    relay.replies[(PID, "r" * 22)] = {"blob": "x", "at": real()}
    relay.now = lambda: real() + hr.TTL_S + 1
    try:
        assert relay.pop_reply(PID, "r" * 22) is None
    finally:
        relay.now = real


def test_size_and_shape(client):
    assert ask(client, blob=b64(b"s" * 5000)).status_code in (400, 413)
    assert ask(client, rid="bad id!").status_code == 400
    assert call(client, "POST", "/v1/replies", j({"rid": "r" * 22, "blob": b64(b"c" * 5000)})).status_code in (400, 413)
    assert client.post("/v1/pairings", json={"pid": b64(b"n" * 16), "key": b64(b"k" * 16), "hello": HELLO}).status_code in (400, 422)
    assert client.post("/v1/pairings", json={"pid": b64(b"n" * 16), "key": "!" * 43, "hello": HELLO}).status_code == 400


def test_unpair_drops_everything(client, relay):
    assert ask(client).status_code == 200
    assert call(client, "DELETE", f"/v1/pairings/{PID}").json() == {"ok": True}
    assert relay.take(PID) is None
    assert ask(client, rid="w" * 22).status_code == 401


def test_at_most_eight_pairings(client):
    for i in range(hr.MAX_PAIRINGS - 1):
        assert client.post("/v1/pairings", json={"pid": b64(bytes([i]) * 16), "key": b64(KEY), "hello": HELLO}).status_code == 200
    assert client.post("/v1/pairings", json={"pid": b64(b"\xff" * 16), "key": b64(KEY), "hello": HELLO}).status_code == 409


def test_pairings_survive_a_restart(tmp_path):
    path = str(tmp_path / "state.json")
    r = hr.Relay(hr.FileStore(path))
    r.pair(PID, KEY, HELLO)
    again = hr.Relay(hr.FileStore(path))
    assert again.key(PID) == KEY
    # The file holds the pairing id, the relay key and the hello: no blob, site or code is ever written.
    assert set(json.loads(Path(path).read_text())[PID]) == {"key", "hello", "added"}


def test_the_log_never_holds_a_blob(client, caplog):
    caplog.set_level("INFO", logger="sphinx.relay")
    assert ask(client, blob=b64(b"SECRETBLOB" * 4)).status_code == 200
    assert caplog.records and all(len(r.getMessage().split()[-1]) <= 6 for r in caplog.records)
    assert not any("SECRET" in r.getMessage() or b64(b"SECRETBLOB" * 4)[:10] in r.getMessage() for r in caplog.records)


def test_the_signature_matches_the_phone_and_the_extension():
    # extension/test/vectors.json (made by pyca/cryptography; crypto.js and the Kotlin client sign the same way)
    v = json.loads(VECTORS.read_text())
    s = v["sign"]
    key = base64.urlsafe_b64decode(v["relay"] + "=")
    assert hr.sign(key, s["method"], s["path"], s["query"], s["ts"], s["nonce"], s["body"].encode()) == s["sig"]
