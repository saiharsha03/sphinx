"""Handoff: the laptop's outbox (phone to laptop) and ciphertext file chunks, with their caps and expiry."""
import json

import pytest
from fastapi.testclient import TestClient

import sphinx_relay as hr
from test_relay import HELLO, KEY, PID, b64, call, j

FID = b64(b"f" * 16)


@pytest.fixture
def relay(monkeypatch):
    monkeypatch.setattr(hr, "WAIT_S", 0.3)
    return hr.Relay(hr.FileStore(None))


@pytest.fixture
def client(relay):
    c = TestClient(hr.create_app(relay, register_token=""))
    assert c.post("/v1/pairings", json={"pid": PID, "key": b64(KEY), "hello": HELLO}).status_code == 200
    return c


def put(client, n, of, data, fid=FID):
    return call(client, "PUT", f"/v1/files/{fid}/{n}", j({"blob": b64(data)}), query=f"of={of}")


def test_a_handoff_waits_in_the_laptops_outbox_until_acked(client):
    blob = b64(b"s" * 64)
    assert call(client, "POST", "/v1/outbox", j({"rid": "h" * 22, "blob": blob})).json() == {"queued": True}
    assert call(client, "GET", "/v1/outbox").json() == {"items": [{"rid": "h" * 22, "blob": blob}]}
    assert call(client, "GET", "/v1/outbox").json()["items"]            # still there until acked
    assert call(client, "POST", "/v1/outbox/ack", j({"rids": ["h" * 22]})).json() == {"acked": 1}
    assert call(client, "GET", "/v1/outbox").json() == {"items": []}
    # The same rid twice is refused; unsigned calls get nothing.
    call(client, "POST", "/v1/outbox", j({"rid": "i" * 22, "blob": blob}))
    assert call(client, "POST", "/v1/outbox", j({"rid": "i" * 22, "blob": blob})).status_code == 409
    assert client.get("/v1/outbox").status_code == 401


def test_the_outbox_is_capped_and_expires(client, relay, monkeypatch):
    for i in range(hr.MAX_QUEUED):
        assert call(client, "POST", "/v1/outbox", j({"rid": f"{i:022d}", "blob": b64(b"s" * 64)})).status_code == 200
    assert call(client, "POST", "/v1/outbox", j({"rid": "x" * 22, "blob": b64(b"s" * 64)})).status_code == 429
    real = relay.now
    monkeypatch.setattr(relay, "now", lambda: real() + hr.OUT_TTL_S + 1)
    assert relay.take_out(PID) == []


def test_a_file_goes_up_in_chunks_and_comes_down_as_it_went(client):
    parts = [b"a" * 100, b"b" * 50]
    for n, d in enumerate(parts):
        assert put(client, n, 2, d).json() == {"ok": True}
    for n, d in enumerate(parts):
        assert call(client, "GET", f"/v1/files/{FID}/{n}").json() == {"blob": b64(d)}
    assert put(client, 0, 2, parts[0]).status_code == 409                # a chunk is written once
    assert put(client, 1, 3, parts[1]).status_code == 409                # the same file can't change its length
    assert call(client, "DELETE", f"/v1/files/{FID}").json() == {"ok": True}
    assert call(client, "GET", f"/v1/files/{FID}/0").status_code == 404


def test_chunks_and_files_have_hard_caps(client, relay, monkeypatch):
    assert put(client, 0, hr.FILE_CHUNKS + 1, b"a" * 100).status_code == 400   # more chunks than a file may have
    assert put(client, 3, 2, b"a" * 100).status_code == 400                    # an index past the end
    assert put(client, 0, 1, b"a" * 16).status_code == 400                     # not even a tag
    assert put(client, 0, 1, b"a" * (hr.CHUNK_MAX + 1)).status_code in (400, 413)
    assert call(client, "PUT", "/v1/files/short/0", j({"blob": b64(b"a" * 100)}), query="of=1").status_code == 400
    # A pairing's storage, then the relay's, run out: refused, never evicted.
    monkeypatch.setattr(hr, "PAIR_FILE_BYTES", 250)
    assert put(client, 0, 3, b"a" * 200).status_code == 200
    assert put(client, 1, 3, b"a" * 100).status_code == 507
    monkeypatch.setattr(hr, "PAIR_FILE_BYTES", 10_000)
    monkeypatch.setattr(hr, "FILE_BYTES_ALL", 260)
    assert put(client, 1, 3, b"a" * 100).status_code == 507
    # A body far over the limit is refused before it is read.
    big = call(client, "PUT", f"/v1/files/{FID}/2", b"x" * (hr.FILE_BODY_MAX + 10), query="of=3")
    assert big.status_code == 413


def test_files_expire_and_go_with_an_unpair(client, relay, monkeypatch):
    put(client, 0, 1, b"a" * 100)
    real = relay.now
    monkeypatch.setattr(relay, "now", lambda: real() + hr.FILE_TTL_S + 1)
    assert relay.get_chunk(PID, FID, 0) is None
    monkeypatch.setattr(relay, "now", real)
    put(client, 0, 1, b"a" * 100, fid=b64(b"g" * 16))
    call(client, "POST", "/v1/outbox", j({"rid": "h" * 22, "blob": b64(b"s" * 64)}))
    relay.unpair(PID)
    assert relay.files == {} and relay.outbox == {}


def test_another_pairing_never_reads_my_chunks(client):
    put(client, 0, 1, b"a" * 100)
    other = b64(b"o" * 16)
    client.post("/v1/pairings", json={"pid": other, "key": b64(b"k" * 32), "hello": HELLO})
    assert call(client, "GET", f"/v1/files/{FID}/0", key=b"k" * 32, pid=other).status_code == 404
    assert call(client, "GET", "/v1/outbox", key=b"k" * 32, pid=other).json() == {"items": []}
