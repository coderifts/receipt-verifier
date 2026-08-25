"""
Unit tests for the verify pipeline.

Run:
    python3 -m unittest -v
"""

import unittest

import _ed25519 as ed
from coderifts_verify import verify_bundle, content_hash
from issuer import build_signed_bundle

REF = "refs/heads/main"
CONTRACT = b'{"openapi":"3.0.0"}'
NOW = 1_000_000


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk = ed.keypair(b"\x07" * 32)
        self.other_sk, self.other_pk = ed.keypair(b"\x09" * 32)

    def make(self, verdict="PASS", version=7, ref=REF, issued_at=NOW,
             ttl=300, sk=None, pk=None):
        return build_signed_bundle(
            CONTRACT, verdict, version,
            private_key=sk or self.sk, public_key=pk or self.pk,
            ref=ref, issued_at=issued_at, ttl_seconds=ttl)

    def test_happy_pass_allows(self):
        r = verify_bundle(self.make(), CONTRACT, self.pk, REF, -1, NOW)
        self.assertTrue(r.ok)
        self.assertEqual(r.action, "allow")
        self.assertEqual(r.new_last_seen, 7)

    def test_block_denies(self):
        r = verify_bundle(self.make("BLOCK", 8), CONTRACT, self.pk, REF, -1, NOW)
        self.assertTrue(r.ok)
        self.assertEqual(r.action, "deny")

    def test_require_approval_holds(self):
        r = verify_bundle(self.make("REQUIRE_APPROVAL", 8), CONTRACT, self.pk, REF, -1, NOW)
        self.assertTrue(r.ok)
        self.assertEqual(r.action, "hold")

    def test_hash_pin_mismatch(self):
        r = verify_bundle(self.make(), CONTRACT + b"x", self.pk, REF, -1, NOW)
        self.assertFalse(r.ok)
        self.assertIn("hash pin", r.reason)

    def test_rollback_rejected(self):
        r = verify_bundle(self.make(version=5), CONTRACT, self.pk, REF, 7, NOW)
        self.assertFalse(r.ok)
        self.assertIn("rollback", r.reason)

    def test_expired_rejected(self):
        r = verify_bundle(self.make(), CONTRACT, self.pk, REF, -1, NOW + 301)
        self.assertFalse(r.ok)
        self.assertIn("expired", r.reason)

    def test_wrong_ref_rejected(self):
        r = verify_bundle(self.make(ref="refs/heads/dev"), CONTRACT, self.pk, REF, -1, NOW)
        self.assertFalse(r.ok)
        self.assertIn("ref mismatch", r.reason)

    def test_untrusted_signer_rejected(self):
        b = self.make(sk=self.other_sk, pk=self.other_pk)
        r = verify_bundle(b, CONTRACT, self.pk, REF, -1, NOW)
        self.assertFalse(r.ok)
        self.assertIn("signature invalid", r.reason)

    def test_mutated_field_breaks_signature(self):
        b = self.make()
        b["verdict"] = "BLOCK"  # flip verdict after signing
        r = verify_bundle(b, CONTRACT, self.pk, REF, -1, NOW)
        self.assertFalse(r.ok)
        self.assertIn("signature invalid", r.reason)

    def test_content_hash_format(self):
        self.assertTrue(content_hash(b"abc").startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
