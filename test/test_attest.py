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

    def test_host_claimed_commit_label(self):
        """1109 HOST-CLAIMED-COMMIT: class=host_claimed → weaker label, never authorized_and_committed."""
        import json
        from pathlib import Path

        doc = json.loads(Path(__file__).with_name("attest-vectors.json").read_text())
        by_name = {v["name"]: v for v in doc["vectors"]}
        host = by_name["EG-A-HOST-CLAIMED"]
        execv = by_name["EG-A-EXECUTOR-ATTESTED"]

        def run(v):
            return verify_execution_attestation(
                v["token"],
                {"registry": doc["registry"], "intended": {"grant": (v.get("flags") or {}).get("grant")}},
            )

        h = run(host)
        e = run(execv)
        self.assertTrue(h["valid"])
        self.assertEqual(h["status"], "ATTEST_VALID")
        self.assertEqual(h["commit_label"], "authorized_and_host_reported_committed")
        self.assertNotEqual(h["commit_label"], "authorized_and_committed")
        self.assertEqual(e["commit_label"], "authorized_and_committed")
        # Bite: flipping class on HOST would fail the weaker-label assertion.
        self.assertNotEqual(h["commit_label"], e["commit_label"])


if __name__ == "__main__":
    unittest.main()
