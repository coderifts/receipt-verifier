"""1.1.5 (2026-10-25) — Ed25519-only and the per-entry tolerant keyring, in verify.py (stdlib unittest).

The same fixtures as test/key-algorithm-keyring-1.1.5.test.js (which also compares the two CLIs byte for byte):
an ML-DSA-65 public key and a receipt it signed (generated once with Node; public material only), and an
unparseable PEM. MEASURED on 1.1.4: verify.py raised "public key is not Ed25519" while loading such a keyring,
so the Ed25519 key beside it could not verify anything.
"""
import hashlib
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from verify import (  # noqa: E402
    _verify_receipt,
    classify_public_key_pem,
    keyring_from_document,
    spki_algorithm_oid,
    spki_der_from_pem,
)

with open(os.path.join(HERE, "fixtures-key-alg-1.1.5.json"), encoding="utf-8") as fh:
    ALG = json.load(fh)
with open(os.path.join(HERE, "fixtures-keys.json"), encoding="utf-8") as fh:
    FIXTURE_KEYS = json.load(fh)
with open(os.path.join(HERE, "fixtures-receipt.txt"), encoding="utf-8") as fh:
    TOKEN = fh.read().strip()
# 10t-rv (2026-11-05): fixtures-keys.json holds a TEST key (test-fixture-k1); this is its receipt. TOKEN (the real
# 2026-07-k1 receipt) stays for the pinned-snapshot case.
with open(os.path.join(HERE, "fixtures-receipt-test-k1.txt"), encoding="utf-8") as fh:
    FIXTURE_TOKEN = fh.read().strip()
with open(os.path.join(HERE, "..", "keys", "coderifts-keys.json"), encoding="utf-8") as fh:
    PIN = json.load(fh)


def ctx_for(keys, warnings=None):
    return {"keyring": keyring_from_document({"keys": keys}, "test", warnings), "expected_kid": None}


class TestKeyAlgorithm(unittest.TestCase):
    def test_oid_and_digest_of_the_fixture_key(self):
        pem = FIXTURE_KEYS["keys"][0]["public_key_pem"]
        der = spki_der_from_pem(pem)
        self.assertEqual(spki_algorithm_oid(der), "1.3.101.112")
        self.assertEqual(classify_public_key_pem(pem)["key_sha256"], hashlib.sha256(der).hexdigest())

    def test_mldsa_is_named_from_the_pem(self):
        c = classify_public_key_pem(ALG["mldsa_public_key_pem"])
        self.assertIsNone(c["public_key"])
        self.assertEqual(c["unsupported_alg"], "ML-DSA-65")

    def test_E_mldsa_signed_receipt_is_invalid(self):
        ctx = ctx_for([{"kid": "pq-1", "alg": "ML-DSA-65", "status": "active", "public_key_pem": ALG["mldsa_public_key_pem"]}])
        r = _verify_receipt(ALG["mldsa_signed_receipt"], ctx)
        self.assertFalse(r["valid"])
        self.assertEqual(r["status"], "INVALID_SIGNATURE")
        self.assertEqual(r["reason"], "unsupported key algorithm: ML-DSA-65")

    def test_A_declared_alg_over_an_ed25519_pem_is_refused(self):
        ctx = ctx_for([dict(k, alg="ML-DSA-65") for k in FIXTURE_KEYS["keys"]])
        self.assertEqual(_verify_receipt(FIXTURE_TOKEN, ctx)["reason"], "unsupported key algorithm: ML-DSA-65")

    def test_C_bad_pem_is_skipped_and_named(self):
        warnings = []
        ctx = ctx_for(FIXTURE_KEYS["keys"] + [{"kid": "pq-1", "public_key_pem": ALG["bad_pem"]}], warnings)
        self.assertTrue(_verify_receipt(FIXTURE_TOKEN, ctx)["valid"])
        self.assertEqual(warnings, ["registry entry pq-1: unparseable public_key_pem — skipped"])

    def test_D_missing_pem_is_skipped_and_named(self):
        warnings = []
        ctx = ctx_for(FIXTURE_KEYS["keys"] + [{"kid": "pq-1", "public_key_jwk": {"kty": "AKP"}}], warnings)
        self.assertTrue(_verify_receipt(FIXTURE_TOKEN, ctx)["valid"])
        self.assertEqual(warnings, ["registry entry pq-1: missing public_key_pem — skipped"])

    def test_pinned_snapshot_fixture_is_revoked_key(self):
        # 1.1.8 (2026-11-04): 2026-07-k1 is revoked (compromised_at 2026-07-01); the fixture was signed
        # by it on 2026-08-26. 1.1.5-1.1.7: retired -> RETIRED_KEY_VALID_AT_ISSUE.
        ctx = ctx_for(PIN["keys"])
        r = _verify_receipt(TOKEN, ctx)
        self.assertFalse(r["valid"])
        self.assertEqual(r["status"], "REVOKED_KEY")


if __name__ == "__main__":
    unittest.main()
