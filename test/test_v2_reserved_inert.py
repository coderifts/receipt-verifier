"""applied_policy_hash is known-inert on the Python grant verifier (1942 verifier-admits).

Twin of test/v2-reserved-inert.test.js for the 1942 field. Dual-accept:
  (a) old grant without the field still verifies
  (b) grant carrying it verifies, and the value is not a gate
  (c) a truly unknown field is still unknown_field
"""
import json
import os
import sys
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from verify_grant import (  # noqa: E402
    V2_REQUIRED_STRINGS,
    V2_RESERVED_INERT,
    signing_input_v2,
    verify_execution_grant,
)
from verify import sha256hex  # noqa: E402


def sha(v):
    return "sha256:" + sha256hex(str(v))


def b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


KID = "RESERVED-PY-KEY"
NOW = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
NOW_MS = NOW.timestamp() * 1000


class TestV2ReservedInert(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.ctx = {"public_key": self.public, "expected_kid": None}
        self.body = {
            "v": "cr.exec.v2",
            "kid": KID,
            "grant_id": "g-reserved-py-1",
            "receipt_hash": sha("receipt"),
            "tenant_id": "tenant",
            "executor_id": "executor",
            "adapter_id": "adapter",
            "operation": "publish",
            "target_uri": "db://host/table",
            "expected_state_token": "state",
            "after_payload_hash": sha("the authorized bytes"),
            "nonce_hash": sha("nonce"),
            "policy_hash": sha("policy"),
            "audience_hash": sha("audience"),
            "not_before": "2026-09-09T11:59:59Z",
            "expires_at": "2026-09-09T12:10:00Z",
            "max_attempts": 1,
        }
        self.intended = {
            "operation": "publish",
            "target_uri": "db://host/table",
            "after_payload": "the authorized bytes",
        }

    def mint(self, extra=None):
        body = dict(self.body)
        if extra:
            body.update(extra)
        sig = self.private.sign(signing_input_v2(body).encode("utf-8"))
        token = b64url(json.dumps(body, separators=(",", ":")).encode("utf-8")) + "." + b64url(sig)
        return token

    def ask(self, token, intended=None):
        opts = {"now": NOW_MS + 1}
        if intended is not None:
            opts["intended"] = intended
        return verify_execution_grant(token, self.ctx, opts)

    def verdict(self, r):
        return f"{r['valid']}/{r['status']}/{r.get('reason') or '-'}"

    def test_reserved_names_match_js(self):
        self.assertEqual(
            tuple(sorted(V2_RESERVED_INERT)),
            ("applied_policy_hash", "call_hash", "executor_image_digest"),
        )
        for name in V2_RESERVED_INERT:
            self.assertNotIn(name, V2_REQUIRED_STRINGS)

    def test_a_grant_without_the_field_still_verifies(self):
        r = self.ask(self.mint(), self.intended)
        self.assertEqual(self.verdict(r), "True/GRANT_CURRENT/-")

    def test_b_grant_carrying_applied_policy_hash_is_inert(self):
        token = self.mint({"applied_policy_hash": sha("evaluated")})
        r = self.ask(token, self.intended)
        self.assertEqual(self.verdict(r), "True/GRANT_CURRENT/-")
        self.assertEqual(r["payload"]["applied_policy_hash"], sha("evaluated"))
        ignored = dict(self.intended)
        ignored["applied_policy_hash"] = sha("something else entirely")
        self.assertEqual(self.verdict(self.ask(token, ignored)), "True/GRANT_CURRENT/-")

    def test_c_unknown_field_still_fail_closed(self):
        r = self.ask(self.mint({"surprise": "x"}))
        self.assertEqual(self.verdict(r), "False/MALFORMED/unknown_field")

    def test_nonsense_value_is_still_inert(self):
        r = self.ask(self.mint({"applied_policy_hash": "not-even-a-digest"}), self.intended)
        self.assertTrue(r["valid"], "a nonsense value was rejected — then it is NOT inert")
        self.assertEqual(r["status"], "GRANT_CURRENT")


if __name__ == "__main__":
    unittest.main()
