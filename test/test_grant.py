"""cr.exec.v1 grant verifier — stdlib unittest, mirrors verify-grant.js exports."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from verify_grant import (  # noqa: E402
    CLOCK_SKEW_LEEWAY_MS,
    GRANT_VERSION,
    GRANT_VERSION_V2,
    SIGNING_PREFIX,
    compute_scope_hash,
    verify_execution_grant,
)


class TestGrantConstants(unittest.TestCase):
    def test_tags(self):
        self.assertEqual(GRANT_VERSION, "cr.exec.v1")
        self.assertEqual(GRANT_VERSION_V2, "cr.exec.v2")
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

    def test_grant_swap_each_binding_holds(self):
        """1109 GRANT-SWAP: A's token + B's intended → GRANT_UNBOUND/target_mismatch."""
        import json
        from pathlib import Path
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        doc = json.loads(Path(__file__).with_name("grant-vectors.json").read_text())
        pub = load_pem_public_key(doc["public_key_pem"].encode("utf-8"))
        ctx = {"public_key": pub, "expected_kid": doc["kid"]}
        by_name = {v["name"]: v for v in doc["vectors"]}
        a, b = by_name["EG2-SWAP-A"], by_name["EG2-SWAP-B"]

        def intended(v):
            f = v.get("flags") or {}
            return {
                "operation": f.get("intended-operation"),
                "target_uri": f.get("intended-target"),
                "audience": f.get("intended-audience"),
                "executor_id": f.get("intended-executor"),
                "adapter_id": f.get("intended-adapter"),
                "after_payload": f.get("after_payload"),
                "receipt_token": f.get("receipt"),
            }

        paired = verify_execution_grant(a["token"], ctx, {"intended": intended(a)})
        self.assertTrue(paired["valid"])
        self.assertEqual(paired["status"], "GRANT_CURRENT")

        swapped = verify_execution_grant(a["token"], ctx, {"intended": intended(b)})
        self.assertFalse(swapped["valid"])
        self.assertEqual(swapped["status"], "GRANT_UNBOUND")
        self.assertEqual(swapped["reason"], "target_mismatch")
        # Bite: pairing correctly here would make the INVALID assertion fail.
        self.assertNotEqual(paired["status"], "GRANT_UNBOUND")


if __name__ == "__main__":
    unittest.main()
