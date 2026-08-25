"""
Schema conformance tests.

Run:
    python3 -m unittest test_schema -v
"""

import unittest

import _ed25519 as ed
from issuer import build_signed_bundle
from schema_validate import validate_bundle_schema

CONTRACT = b'{"openapi":"3.0.0"}'


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk = ed.keypair(b"\x07" * 32)

    def good(self):
        return build_signed_bundle(CONTRACT, "PASS", 7, self.sk, self.pk,
                                   issued_at=1_000_000, ttl_seconds=300)

    def test_issued_bundle_conforms(self):
        self.assertEqual(validate_bundle_schema(self.good()), [])

    def test_missing_field_caught(self):
        b = self.good()
        del b["signature"]
        errs = validate_bundle_schema(b)
        self.assertTrue(any("signature" in e for e in errs))

    def test_extra_field_caught(self):
        b = self.good()
        b["surprise"] = 1
        errs = validate_bundle_schema(b)
        self.assertTrue(any("unexpected field" in e for e in errs))

    def test_bad_verdict_caught(self):
        b = self.good()
        b["verdict"] = "MAYBE"
        errs = validate_bundle_schema(b)
        self.assertTrue(any("verdict" in e for e in errs))

    def test_bad_content_hash_caught(self):
        b = self.good()
        b["content_hash"] = "md5:abc"
        errs = validate_bundle_schema(b)
        self.assertTrue(any("content_hash" in e for e in errs))

    def test_negative_version_caught(self):
        b = self.good()
        b["version"] = -1
        errs = validate_bundle_schema(b)
        self.assertTrue(any("version" in e for e in errs))


if __name__ == "__main__":
    unittest.main()
