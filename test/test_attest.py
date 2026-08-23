"""cr.exec.attest.v1 verifier — stdlib unittest, mirrors verify-attest.js exports."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from verify_attest import (  # noqa: E402
    ATTEST_VERSION,
    CLOCK_SKEW_LEEWAY_MS,
    ENVELOPE_TAG,
    SIGNING_PREFIX,
    verify_execution_attestation,
)


class TestAttestConstants(unittest.TestCase):
    def test_tags(self):
        self.assertEqual(ATTEST_VERSION, "cr.exec.attest.v1")
        self.assertEqual(SIGNING_PREFIX, "crexecattest.v1")
        self.assertEqual(ENVELOPE_TAG, "cr.exec.attest.v1")
        self.assertEqual(CLOCK_SKEW_LEEWAY_MS, 30_000)

    def test_malformed_empty(self):
        r = verify_execution_attestation("", {"registry": {"keys": []}})
        self.assertFalse(r["valid"])
        self.assertEqual(r["status"], "ATTEST_MALFORMED")


if __name__ == "__main__":
    unittest.main()
