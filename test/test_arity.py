"""1129 unified (token, opts) — Python mirrors of the JS arity tests."""
import json
import os
import sys
import unittest
import warnings

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from arity import reset_warned_for_test  # noqa: E402
from verify import key_from_pem, verify_chain, verify_receipt  # noqa: E402
from verify_attest import verify_execution_attestation  # noqa: E402
from verify_grant import GRANT_VERSION_V2, verify_execution_grant  # noqa: E402
from verify_monitor import verify_monitoring_attestation  # noqa: E402
from verify_toolset import verify_toolset_attestation  # noqa: E402

HERE = os.path.dirname(__file__)


def _load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return json.load(fh)


class TestUnifiedArity(unittest.TestCase):
    def setUp(self):
        reset_warned_for_test()
        rec = _load("vectors.json")
        self.rec_token = next(v["token"] for v in rec["vectors"] if v["name"] == "valid_v4")
        self.rec_ctx = {
            "public_key": key_from_pem(rec["public_key_pem"]),
            "expected_kid": rec["kid"],
        }
        grants = _load("grant-vectors.json")
        self.g_token = next(v["token"] for v in grants["vectors"] if v["name"] == "EG-VALID")
        self.g_ctx = {
            "public_key": key_from_pem(grants["public_key_pem"]),
            "expected_kid": grants["kid"],
        }
        self.g_intended = {
            "operation": grants["operation"],
            "target_id": grants["target_id"],
            "audience": grants["audience"],
            "after_payload": grants["after_payload"],
            "receipt_token": grants["receipt"],
        }
        self.att = _load("attest-vectors.json")
        self.ts = _load("toolset-vectors.json")
        self.mon = _load("monitor-vectors.json")

    def test_v2_tag(self):
        self.assertEqual(GRANT_VERSION_V2, "cr.exec.v2")

    def test_receipt_unified(self):
        r = verify_receipt(self.rec_token, {"ctx": self.rec_ctx})
        self.assertTrue(r["valid"])

    def test_chain_unified(self):
        r = verify_chain([self.rec_token], {"ctx": self.rec_ctx})
        self.assertIsInstance(r["valid"], bool)

    def test_grant_unified(self):
        r = verify_execution_grant(self.g_token, {"ctx": self.g_ctx, "intended": self.g_intended})
        self.assertEqual(r["status"], "GRANT_CURRENT")

    def test_attest_opts_ctx_registry(self):
        v = next(x for x in self.att["vectors"] if x["name"] == "EG-A-VALID")
        r = verify_execution_attestation(v["token"], {"ctx": {"registry": self.att["registry"]}})
        self.assertTrue(r["valid"])

    def test_toolset_unified_opts_dict(self):
        v = next(x for x in self.ts["vectors"] if x["id"] == "TS-A-VALID")
        r = verify_toolset_attestation(v["token"], {
            "ctx": {"registry": self.ts["registry"], "entries": self.ts["entries"]},
        })
        self.assertTrue(r.get("valid") or r.get("ok") or r.get("status") in (
            "TOOLSET_ATTEST_VALID", "TS_ATTEST_VALID",
        ))

    def test_monitor_opts_ctx_registry(self):
        v = next(x for x in self.mon["vectors"] if x.get("name") == "MON-A-VALID")
        r = verify_monitoring_attestation(v["token"], {"ctx": {"registry": self.mon["registry"]}})
        self.assertTrue(r.get("valid") or r.get("status") == "MON_ATTEST_VALID")

    def test_wrapper_warns_once_and_forwards(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            a = verify_receipt(self.rec_token, self.rec_ctx, {})
            b = verify_receipt(self.rec_token, self.rec_ctx, {})
            self.assertTrue(a["valid"] and b["valid"])
            dep = [w for w in caught
                   if issubclass(w.category, DeprecationWarning)
                   and "verify_receipt" in str(w.message)]
            self.assertEqual(len(dep), 1, [str(w.message) for w in dep])

    def test_grant_wrapper_forwards(self):
        r = verify_execution_grant(self.g_token, self.g_ctx, {"intended": self.g_intended})
        self.assertTrue(r["valid"])
        self.assertEqual(r["status"], "GRANT_CURRENT")

    def test_attest_extra_positional_raises(self):
        with self.assertRaises(TypeError):
            verify_execution_attestation("t", {}, {})

    def test_monitor_extra_positional_raises(self):
        with self.assertRaises(TypeError):
            verify_monitoring_attestation("t", {}, {})


if __name__ == "__main__":
    unittest.main()
