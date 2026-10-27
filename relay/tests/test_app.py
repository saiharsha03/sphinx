"""The app's self-update: a release in SPHINX_APP_DIR (app.json and the APK it names), read fresh on every call."""
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

import sphinx_relay as hr
from test_relay import HELLO, KEY, PID, b64, call

APK = b"PK\x03\x04" + b"a" * 300
META = {"versionCode": 7, "versionName": "1.2.0", "sha256": hashlib.sha256(APK).hexdigest(), "size": len(APK),
        "file": "sphinx-1.2.0.apk", "notes": "fixes"}


@pytest.fixture
def relay(monkeypatch):
    monkeypatch.setattr(hr, "_app_refused", None)
    return hr.Relay(hr.FileStore(None))


def make_client(relay, app_dir):
    c = TestClient(hr.create_app(relay, register_token="", insecure_dev=True, app_dir=app_dir))
    assert c.post("/v1/pairings", json={"pid": PID, "key": b64(KEY), "hello": HELLO}).status_code == 200
    return c


def write_release(folder, meta=META, apk=APK):
    folder.mkdir(exist_ok=True)
    (folder / "app.json").write_text(json.dumps(meta))
    if apk is not None:
        (folder / meta["file"]).write_bytes(apk)


def test_without_a_folder_there_is_no_release(relay):
    c = make_client(relay, None)
    assert call(c, "GET", "/v1/app").status_code == 404
    assert call(c, "GET", "/v1/app/file").status_code == 404


def test_a_release_is_served_with_its_sha(relay, tmp_path):
    write_release(tmp_path)
    c = make_client(relay, str(tmp_path))
    assert call(c, "GET", "/v1/app").json() == META
    r = call(c, "GET", "/v1/app/file")
    assert r.status_code == 200 and r.content == APK
    assert r.headers["x-sphinx-sha256"] == META["sha256"]
    assert r.headers["content-type"] == "application/vnd.android.package-archive"
    assert r.headers["content-length"] == str(len(APK))
    # Replaced while the relay runs: the next call sees the new one, nothing is cached.
    apk2 = APK + b"b"
    write_release(tmp_path, {**META, "versionCode": 8, "sha256": hashlib.sha256(apk2).hexdigest(), "size": len(apk2)}, apk2)
    assert call(c, "GET", "/v1/app").json()["versionCode"] == 8
    assert call(c, "GET", "/v1/app/file").content == apk2


def test_a_bad_release_is_no_release(relay, tmp_path, caplog):
    caplog.set_level("WARNING", logger="sphinx.relay")
    c = make_client(relay, str(tmp_path))
    bad = [{**META, "sha256": "X" * 64}, {**META, "file": "../etc/passwd.apk"}, {**META, "file": "sphinx.zip"},
           {**META, "versionCode": 0}, {**META, "size": len(APK) + 1}, {**META, "notes": "n" * 2001}]
    for meta in bad:
        write_release(tmp_path, meta, apk=None)
        (tmp_path / META["file"]).write_bytes(APK)
        assert call(c, "GET", "/v1/app").status_code == 404, meta
        assert call(c, "GET", "/v1/app/file").status_code == 404, meta
    (tmp_path / "app.json").write_text("{not json")
    assert call(c, "GET", "/v1/app").status_code == 404
    write_release(tmp_path, apk=None)
    (tmp_path / META["file"]).unlink()
    assert call(c, "GET", "/v1/app").status_code == 404                       # the named APK is missing
    # Logged by reason only, never the json's text.
    assert not any("passwd" in r.getMessage() or "X" * 8 in r.getMessage() for r in caplog.records)
    assert any("app release refused" in r.getMessage() for r in caplog.records)


def test_a_refusal_is_logged_once(relay, tmp_path, caplog):
    caplog.set_level("WARNING", logger="sphinx.relay")
    c = make_client(relay, str(tmp_path))
    write_release(tmp_path, {**META, "sha256": "X" * 64})
    for _ in range(3):
        assert call(c, "GET", "/v1/app").status_code == 404
    assert sum("app release refused" in r.getMessage() for r in caplog.records) == 1


def test_the_app_routes_are_signed(relay, tmp_path):
    write_release(tmp_path)
    c = make_client(relay, str(tmp_path))
    assert c.get("/v1/app").status_code == 401
    assert c.get("/v1/app/file").status_code == 401
    assert call(c, "GET", "/v1/app", key=b"x" * 32).status_code == 401
