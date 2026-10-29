"""1.1.6 — expiry applies after the retired-key rule in verify.py (mirrors verify.js; RECEIPT_FORMAT §7).

MEASURED in round 10b: derive_status returned RETIRED_KEY_VALID_AT_ISSUE before the expiry check, so an
expired v4 receipt under a retired key verified valid:true. Ephemeral Ed25519 key; no network.
"""
import base64
import hashlib
import json
import os
import sys
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from verify import (  # noqa: E402
    _verify_receipt,
    canonical_json,
    derive_status,
    keyring_from_document,
    reconstruct_signed_input,
)

KID = "retired-expiry-py-k1"
KEY = Ed25519PrivateKey.generate()
PEM = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
HOUR = 3600_000
NOW = int(datetime.now(timezone.utc).timestamp()) * 1000
TS = NOW - 6 * HOUR
RETIRED = {"status": "retired", "retired_at": None}


def iso(ms):
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def mint(ts, exp):
    payload = {"v": 4, "kid": KID, "fp": "sha256:" + hashlib.sha256(b"fp").hexdigest(), "prev": "null", "caller": "bundle",
               "ts": iso(ts), "reg": "", "ir": "", "expires_at": iso(exp),
               "bh": "sha256:" + hashlib.sha256(canonical_json({"decision": "ALLOW"}).encode()).hexdigest()}
    sig = KEY.sign(reconstruct_signed_input(payload).encode("utf-8"))
    return b64u(json.dumps(payload, separators=(",", ":")).encode()) + "." + b64u(sig), payload


def verify(token, retired_at):
    entry = {"kid": KID, "public_key_pem": PEM, "status": "retired", "valid_from": None, "retired_at": iso(retired_at)}
    return _verify_receipt(token, {"keyring": keyring_from_document({"keys": [entry]}, "test"), "expected_kid": None})


class TestRetiredKeyExpiry(unittest.TestCase):
    def test_expired_under_retired_key_is_verified_expired(self):
        token, _ = mint(TS, TS + 4 * HOUR)
        r = verify(token, TS + HOUR)
        self.assertEqual(r["status"], "VERIFIED_EXPIRED")
        self.assertFalse(r["valid"])

    def test_derive_status_expired_under_retired_key(self):
        _, payload = mint(TS, TS + 4 * HOUR)
        entry = dict(RETIRED, retired_at=iso(TS + HOUR))
        self.assertEqual(derive_status(payload, entry, {"now": NOW}), "VERIFIED_EXPIRED")
        self.assertEqual(derive_status(payload, entry, {"now": TS + 2 * HOUR}), "RETIRED_KEY_VALID_AT_ISSUE")

    def test_inside_the_leeway_is_still_valid_at_issue(self):
        token, _ = mint(TS, NOW - 10_000)
        r = verify(token, TS + HOUR)
        self.assertEqual(r["status"], "RETIRED_KEY_VALID_AT_ISSUE")
        self.assertTrue(r["valid"])

    def test_inside_the_window_unchanged(self):
        token, _ = mint(TS, NOW + HOUR)
        r = verify(token, TS + HOUR)
        self.assertEqual(r["status"], "RETIRED_KEY_VALID_AT_ISSUE")
        self.assertTrue(r["valid"])

    def test_signed_after_retirement_still_refused(self):
        token, _ = mint(TS, NOW + HOUR)
        r = verify(token, TS - HOUR)
        self.assertFalse(r["valid"])
        self.assertEqual(r["status"], "KEY_RETIRED_AFTER_SIGNING")


if __name__ == "__main__":
    unittest.main()
