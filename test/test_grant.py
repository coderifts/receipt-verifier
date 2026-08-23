"""cr.exec.v1 grant verifier — stdlib unittest, mirrors verify-grant.js exports."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from verify_grant import (  # noqa: E402
    CLOCK_SKEW_LEEWAY_MS,
    GRANT_VERSION,
    SIGNING_PREFIX,
    compute_scope_hash,
    verify_execution_grant,
)


class TestGrantConstants(unittest.TestCase):
    def test_tags(self):
        self.assertEqual(GRANT_VERSION, "cr.exec.v1")
        self.assertEqual(SIGNING_PREFIX, "crexec.v1")
        self.assertEqual(CLOCK_SKEW_LEEWAY_MS, 30_000)

    def test_scope_hash_golden(self):
        h = compute_scope_hash(operation="merge", target_id="t", after_payload='{"ok":true}')
        self.assertEqual(
            h,
            "sha256:bda9dac1974036a2e2de4e882a9207bed2dc6f0f4d360db5a60f877771172cbe",
        )

    def test_malformed_empty(self):
        r = verify_execution_grant("", {"public_key": None, "expected_kid": None})
        self.assertFalse(r["valid"])
        self.assertEqual(r["status"], "MALFORMED")


if __name__ == "__main__":
    unittest.main()
