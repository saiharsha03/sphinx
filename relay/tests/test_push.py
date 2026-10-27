"""The fast wake (FCM carrying the sealed request), the phone's push token, the laptop's status and the no-wait inbox."""
import json
import time

import pytest
from fastapi.testclient import TestClient

import sphinx_relay as hr
from test_relay import HELLO, KEY, PID, ask, b64, call, j

TOKEN = "fcm-token_" + "a" * 140


class FakeFcm:
    def __init__(self, on=True):
        self.on, self.woken = on, []

    def available(self):
        return self.on

    def wake(self, pid, token, sphinx):
        self.woken.append((pid, token, sphinx))


@pytest.fixture
def fcm():
    return FakeFcm()


@pytest.fixture
def relay(monkeypatch, fcm):
    monkeypatch.setattr(hr, "WAIT_S", 0.3)
    return hr.Relay(hr.FileStore(None), fcm=fcm)


@pytest.fixture
def client(relay):
    c = TestClient(hr.create_app(relay, register_token="", insecure_dev=True))
    assert c.post("/v1/pairings", json={"pid": PID, "key": b64(KEY), "hello": HELLO}).status_code == 200
    return c


def test_carry_is_every_blob_oldest_first_or_none():
    # Their sealed counters must arrive in order (review 2026-10-27: newest first made the older one a replay).
    q = [{"pid": PID, "rid": f"r{i:021d}", "blob": "b" * 1000, "at": i} for i in (2, 0, 1)]
    got = json.loads(hr.carry(q))
    assert [b["rid"] for b in got] == ["r000000000000000000000", "r000000000000000000001", "r000000000000000000002"]
    assert set(got[0]) == {"pid", "rid", "blob"}
    assert len(hr.carry(q)) <= hr.CARRY_MAX
    # Not all of them fit: none is carried, the phone fetches them all in order.
    assert hr.carry([{"pid": PID, "rid": f"r{i:021d}", "blob": "b" * 1000, "at": i} for i in range(5)]) is None
    # Not even one fits: a plain sync.
    assert hr.carry([{"pid": PID, "rid": "r" * 22, "blob": "b" * hr.CARRY_MAX, "at": 0}]) is None
    assert hr.carry([]) is None


def test_the_fcm_message_is_sync_plus_the_carried_blobs_only():
    m = hr.fcm_payload(TOKEN, '[{"pid":"p"}]')["message"]
    assert m["data"] == {"t": "sync", "sphinx": '[{"pid":"p"}]'}
    assert m["token"] == TOKEN and m["android"]["priority"] == "high"
    assert set(m) == {"token", "data", "android"}          # no notification block: Google sees no words
    assert hr.fcm_payload(TOKEN, None)["message"]["data"] == {"t": "sync"}


def test_a_request_wakes_the_phone_through_fcm_with_the_sealed_blob(client, fcm):
    assert call(client, "POST", "/v1/push", j({"token": TOKEN})).json() == {"push": True}
    blob = b64(b"s" * 64)
    assert ask(client, blob=blob).status_code == 200
    (pid, token, carried), = fcm.woken
    assert (pid, token) == (PID, TOKEN)
    assert json.loads(carried) == [{"pid": PID, "rid": "r" * 22, "blob": blob}]
    # The blob still waits in the inbox for the phone's fetch and ack.
    assert [b["rid"] for b in call(client, "GET", "/v1/inbox", query="wait=0").json()["items"]] == ["r" * 22]


def test_no_service_account_means_no_push_and_the_long_poll_stays(client, fcm):
    fcm.on = False
    assert call(client, "POST", "/v1/push", j({"token": TOKEN})).json() == {"push": False}
    assert ask(client).status_code == 200
    assert fcm.woken == []


def test_a_relay_without_fcm_at_all_runs(monkeypatch):
    monkeypatch.delenv("SPHINX_FCM_ACCOUNT", raising=False)
    assert not hr.Fcm(None).available()
    r = hr.Relay(hr.FileStore(None))
    c = TestClient(hr.create_app(r, register_token="", insecure_dev=True))
    assert c.post("/v1/pairings", json={"pid": PID, "key": b64(KEY), "hello": HELLO}).status_code == 200
    assert call(c, "POST", "/v1/push", j({"token": TOKEN})).json() == {"push": False}
    assert ask(c).status_code == 200


def test_the_push_token_is_checked_and_can_be_forgotten(client, relay, fcm):
    for bad in ["short", "a" * 600, "has space" + "a" * 30, "a/b" + "a" * 30]:
        assert call(client, "POST", "/v1/push", j({"token": bad})).status_code in (400,), bad
    assert call(client, "POST", "/v1/push", j({"token": TOKEN})).json() == {"push": True}
    assert relay.pairings()[PID]["push"] == TOKEN
    assert call(client, "POST", "/v1/push", j({"token": ""})).json() == {"push": False}
    assert "push" not in relay.pairings()[PID]
    assert ask(client).status_code == 200
    assert fcm.woken == []
    # Unsigned, nobody sets a token.
    assert client.post("/v1/push", json={"token": TOKEN}).status_code == 401


def test_the_token_survives_a_restart_and_goes_with_an_unpair(tmp_path):
    path = str(tmp_path / "state.json")
    r = hr.Relay(hr.FileStore(path), fcm=FakeFcm())
    r.pair(PID, KEY, HELLO)
    assert r.set_push(PID, TOKEN)
    again = hr.Relay(hr.FileStore(path), fcm=FakeFcm())
    assert again.can_push(PID)
    again.unpair(PID)
    assert not again.can_push(PID) and PID not in json.loads(open(path).read())


def test_status_tells_the_laptop_when_the_phone_last_called_to_the_minute(client, relay, monkeypatch):
    s = call(client, "GET", "/v1/status").json()
    assert s["paired"] is True and s["phone_seen"] is None and s["push"] is False and abs(s["now"] - time.time()) < 5
    # A laptop call doesn't count as the phone.
    assert ask(client).status_code == 200
    assert call(client, "GET", "/v1/status").json()["phone_seen"] is None
    call(client, "GET", "/v1/inbox", query="wait=0")
    seen = call(client, "GET", "/v1/status").json()["phone_seen"]
    assert seen % 60 == 0 and time.time() - seen < 61
    # Unsigned: nothing.
    assert client.get("/v1/status").status_code == 401


def test_the_inbox_never_waits(client):
    # No live connection: the phone's fetch answers at once, with or without the old wait=0.
    for q in ("", "wait=0"):
        t = time.monotonic()
        assert call(client, "GET", "/v1/inbox", query=q).json() == {"items": []}
        assert time.monotonic() - t < 0.25


def test_the_bearer_is_a_signed_jwt_and_fcm_is_called_with_it(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    acct = tmp_path / "sa.json"
    acct.write_text(json.dumps({"project_id": "sphinx-test", "client_email": "x@sphinx-test.iam.gserviceaccount.com",
                                "token_uri": "https://oauth2.googleapis.com/token", "private_key": pem}))
    seen = []

    class R:
        status = 200

        def __init__(self, body):
            self.body = body

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def urlopen(req, timeout):
        seen.append((req.full_url, req.data, dict(req.headers)))
        return R(b'{"access_token": "AT", "expires_in": 3600}' if "oauth2" in req.full_url else b"{}")

    monkeypatch.setattr(hr.urllib.request, "urlopen", urlopen)
    f = hr.Fcm(str(acct))
    assert f.available()
    assert f.send_now(TOKEN, None) == 200
    assert f.send_now(TOKEN, '[]') == 200
    token_calls = [s for s in seen if "oauth2" in s[0]]
    assert len(token_calls) == 1                         # the bearer is reused until it nears expiry
    assert b"jwt-bearer&assertion=" in token_calls[0][1]
    url, body, headers = seen[-1]
    assert url == "https://fcm.googleapis.com/v1/projects/sphinx-test/messages:send"
    assert headers["Authorization"] == "Bearer AT"
    assert json.loads(body)["message"]["data"] == {"t": "sync", "sphinx": "[]"}
