"""Sphinx wire-format vectors from a third implementation (pyca/cryptography), checked by the phone's Kotlin
(app/src/test/java/dev/sphinx/CryptoTest.kt), the extension's crypto.js (test/crypto.test.mjs) and the relay's pytest.
Run:  docker run --rm -v <this dir>:/t python:3.12 sh -c "pip install -q cryptography segno && python /t/make_vectors.py"
Writes vectors.json and qr_vectors.json next to itself. Fixed keys: test values only, never used for real."""
import base64
import hashlib
import hmac
import json
import os
import struct

import segno
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = os.path.dirname(os.path.abspath(__file__))


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def hkdf(ikm, salt, info, n=32):
    return HKDF(hashes.SHA256(), n, salt, info.encode()).derive(ikm)


laptop_priv = bytes(range(1, 33))
phone_priv = bytes(range(101, 133))
lk = X25519PrivateKey.from_private_bytes(laptop_priv)
pk = X25519PrivateKey.from_private_bytes(phone_priv)
laptop_pub = lk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
phone_pub = pk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
shared = pk.exchange(lk.public_key())
pid = b64u(b"P" * 16)
secret = bytes(range(200, 216))
keys = hkdf(shared, secret, f"sphinx v1|{pid}", 64)
l2p, p2l = keys[:32], keys[32:]
relay = hkdf(secret, pid.encode(), "sphinx relay v1")
hk = hkdf(secret, pid.encode(), "sphinx hello v1")
hello = b64u(phone_pub + hmac.new(hk, f"sphinx hello v1|{pid}|{b64u(laptop_pub)}|{b64u(phone_pub)}".encode(), hashlib.sha256).digest())


def seal(key, d, ctr, exp, plain, iv):
    header = struct.pack(">BBqq", 1, ord(d), ctr, exp)
    return b64u(header + iv + AESGCM(key).encrypt(iv, plain, b"sphinx|" + pid.encode() + b"|" + header))


req = json.dumps({"v": 1, "kind": "code.request", "rid": "R" * 22, "body": {"host": "github.com", "user": "work"}}, separators=(",", ":")).encode()
rep = json.dumps({"v": 1, "kind": "code.reply", "rid": "R" * 22, "body": {"ok": True, "code": "123456"}}, separators=(",", ":")).encode()
push = json.dumps({"v": 1, "kind": "handoff.send", "rid": "H" * 22, "body": {"type": "link", "url": "https://example.com/a", "open": True}}, separators=(",", ":")).encode()
# A handoff file chunk: AES-256-GCM under the file's own key, iv = 8 zero bytes + the chunk index (u32, big endian),
# AAD "sphinx file v1|<fid>|<n>|<total>". The key travels only inside a sealed handoff.send.
fkey, fid, fplain = bytes(range(40, 72)), b64u(b"F" * 16), b"hello file " * 20
fblob = b64u(AESGCM(fkey).encrypt(b"\x00" * 8 + struct.pack(">I", 1), fplain, f"sphinx file v1|{fid}|1|3".encode()))
qr = f"sphinx:1?p={pid}&k={b64u(laptop_pub)}&s={b64u(secret)}&r=https://relay.example.com&n=Chrome"
out = {
    "laptop_priv": b64u(laptop_priv), "laptop_pub": b64u(laptop_pub), "phone_priv": b64u(phone_priv), "phone_pub": b64u(phone_pub),
    "shared": b64u(shared), "pid": pid, "secret": b64u(secret), "l2p": b64u(l2p), "p2l": b64u(p2l), "relay": b64u(relay), "hello": hello,
    "qr": qr,
    "request": {"plain": req.decode(), "ctr": 7, "exp": 1_800_000_000_000, "iv": b64u(b"\x11" * 12), "blob": seal(l2p, "q", 7, 1_800_000_000_000, req, b"\x11" * 12)},
    "reply": {"plain": rep.decode(), "ctr": 3, "exp": 1_800_000_000_000, "iv": b64u(b"\x22" * 12), "blob": seal(p2l, "r", 3, 1_800_000_000_000, rep, b"\x22" * 12)},
    "push": {"plain": push.decode(), "ctr": 2, "exp": 1_800_000_000_000, "iv": b64u(b"\x33" * 12), "blob": seal(p2l, "p", 2, 1_800_000_000_000, push, b"\x33" * 12)},
    "file": {"key": b64u(fkey), "fid": fid, "n": 1, "total": 3, "plain": b64u(fplain), "blob": fblob},
    "sign": {"method": "POST", "path": "/v1/requests", "query": "", "ts": "1800000000", "nonce": "N" * 22, "body": '{"rid":"x"}'},
}
s = out["sign"]
canon = f"{s['method']}\n{s['path']}\n{s['query']}\n{s['ts']}\n{s['nonce']}\n{hashlib.sha256(s['body'].encode()).hexdigest()}".encode()
s["sig"] = b64u(hmac.new(relay, canon, hashlib.sha256).digest())
json.dump(out, open(os.path.join(HERE, "vectors.json"), "w"), indent=1)

# QR matrices for the extension's encoder: byte mode, level M, fixed version and mask.
cases = []
for text, version, mask in [("hello", 1, 0), ("sphinx", 2, 3), (qr, 9, 5), (qr, 10, 2), ("x" * 300, 15, 7), ("A1-b2_c3" * 4, 4, 6), ("Sphinx Codes", 3, 1), ("0123456789" * 9, 7, 4)]:
    q = segno.make(text, error="m", version=version, mask=mask, mode="byte", boost_error=False)
    cases.append({"text": text, "version": version, "mask": mask, "rows": ["".join("1" if c else "0" for c in row) for row in q.matrix]})
json.dump(cases, open(os.path.join(HERE, "qr_vectors.json"), "w"))
print("wrote vectors.json and", len(cases), "QR cases")
