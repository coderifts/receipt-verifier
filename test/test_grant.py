"""cr.exec.v1 grant verifier — stdlib unittest, mirrors verify-grant.js exports."""
import os
import sys
import json
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



class TestGrant117(unittest.TestCase):
    """1.1.7 (2026-10-31): v2 `environment`, --intended-environment, and the v2 revoked-key rule.

    MEASURED before (HEAD 2c11499): an `environment` grant was MALFORMED/unknown_field, and a v2 grant
    under a key with status "revoked" was GRANT_CURRENT here while verify-grant.js said
    UNKNOWN_KEY/revoked_kid. Throwaway keys generated per run. Negative first.
    """

    @classmethod
    def setUpClass(cls):
        import base64
        import hashlib
        from datetime import datetime, timedelta, timezone
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from verify import canonical_json

        cls.sk = Ed25519PrivateKey.generate()
        cls.pk = cls.sk.public_key()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        sha = lambda s: "sha256:" + hashlib.sha256(s.encode()).hexdigest()  # noqa: E731
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731

        def grant(**over):
            body = {
                "v": "cr.exec.v2", "kid": "k-117", "grant_id": "g-1", "receipt_hash": sha("r"), "tenant_id": "t1",
                "executor_id": "exec-a", "adapter_id": "fs", "operation": "write", "target_uri": "fs://repo/out.txt",
                "expected_state_token": sha(""), "after_payload_hash": sha("x"), "nonce_hash": sha("n"),
                "policy_hash": sha("p"), "audience_hash": sha("aud"), "not_before": iso(now - timedelta(minutes=1)),
                "expires_at": iso(now + timedelta(minutes=10)), "max_attempts": 1,
            }
            body.update(over)
            sig = cls.sk.sign(("crexec.v2|" + canonical_json(body)).encode("utf-8"))
            return b64(json.dumps(body).encode()) + "." + b64(sig)

        cls.grant = staticmethod(grant)

    def ctx(self):
        return {"public_key": self.pk, "expected_kid": None}

    def test_bad_environment_is_malformed(self):
        for env in (7, "", None, ["production"]):
            r = verify_execution_grant(self.grant(environment=env), self.ctx())
            self.assertEqual((r["status"], r.get("reason")), ("MALFORMED", "bad_environment"), env)

    def test_environment_mismatch(self):
        r = verify_execution_grant(self.grant(environment="production"), self.ctx(), {"intended": {"environment": "staging"}})
        self.assertEqual((r["valid"], r["status"], r["reason"]), (False, "GRANT_UNBOUND", "environment_mismatch"))
        r = verify_execution_grant(self.grant(), self.ctx(), {"intended": {"environment": "production"}})
        self.assertEqual(r["reason"], "environment_mismatch", "absent is not a match")

    def test_v1_with_intended_environment_is_mismatch(self):
        from pathlib import Path
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        doc = json.loads(Path(__file__).with_name("grant-vectors.json").read_text())
        v1 = next(v for v in doc["vectors"] if v["name"] == "EG-VALID")
        ctx = {"public_key": load_pem_public_key(doc["public_key_pem"].encode()), "expected_kid": doc["kid"]}
        r = verify_execution_grant(v1["token"], ctx, {"intended": {"environment": "production"}})
        self.assertEqual((r["status"], r["reason"]), ("GRANT_UNBOUND", "environment_mismatch"))

    def test_v2_revoked_key_is_unknown_key(self):
        ring = {"k-117": {"public_key": self.pk, "status": "revoked", "retired_at": None, "compromised_at": "2026-01-01T00:00:00Z"}}
        r = verify_execution_grant(self.grant(), {"keyring": ring, "expected_kid": None})
        self.assertEqual((r["valid"], r["status"], r["reason"]), (False, "UNKNOWN_KEY", "revoked_kid"))

    def test_environment_grant_is_current(self):
        tok = self.grant(environment="production")
        self.assertEqual(verify_execution_grant(tok, self.ctx())["status"], "GRANT_CURRENT")
        r = verify_execution_grant(tok, self.ctx(), {"intended": {"environment": "production"}})
        self.assertEqual(r["status"], "GRANT_CURRENT")


class TestGrantAddendum(unittest.TestCase):
    """Addendum (2026-10-31 23:05): unknown key status and revoked_at on v2/v1; strict parse of the v2 body.

    MEASURED before: v2 under status "suspended" GRANT_CURRENT; status "active" + revoked_at GRANT_CURRENT
    (v2 and v1); a v2 body with a lone surrogate crashed this CLI's writer (UnicodeEncodeError, from 10l's
    ensure_ascii=False) and 1e400 printed `Infinity`, which is not JSON. Negative first.
    """

    @classmethod
    def setUpClass(cls):
        TestGrant117.setUpClass()
        cls.grant = staticmethod(TestGrant117.grant)
        cls.sk, cls.pk = TestGrant117.sk, TestGrant117.pk

    def ring(self, **extra):
        e = {"public_key": self.pk, "retired_at": None}
        e.update(extra)
        return {"keyring": {"k-117": e}, "expected_kid": None}

    def from_text(self, text):
        import base64
        from verify import canonical_json
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
        try:
            sig = self.sk.sign(("crexec.v2|" + canonical_json(json.loads(text))).encode("utf-8"))
        except Exception:
            sig = b"\0" * 64
        return b64(text.encode("utf-8")) + "." + b64(sig)

    def body(self):
        import base64
        seg = self.grant().split(".")[0]
        raw = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode("utf-8")
        return json.dumps(json.loads(raw), separators=(",", ":"))  # compact, so the replaces below match

    def test_v2_unknown_key_status(self):
        for status in ("suspended", "ACTIVE", ""):
            r = verify_execution_grant(self.grant(), self.ring(status=status))
            self.assertEqual((r["status"], r.get("reason")), ("UNKNOWN_KEY", "unknown_key_status"), status)

    def test_revoked_at_refuses_whatever_the_status(self):
        for status in ("active", "retired", None, "revoked"):
            r = verify_execution_grant(self.grant(), self.ring(status=status, revoked_at="2026-01-01T00:00:00Z",
                                                               compromised_at="2026-01-01T00:00:00Z"))
            self.assertEqual((r["status"], r.get("reason")), ("UNKNOWN_KEY", "revoked_kid"), status)

    def test_strict_v2_body(self):
        text = self.body()
        cases = [
            ("duplicate_key", text[:-1] + ',"executor_id":"exec-b"}'),
            ("duplicate_key", '{"v":"cr.exec.v1",' + text[1:]),
            ("lone_surrogate", text.replace('"tenant_id":"t1"', '"tenant_id":"t\\ud800"')),
            ("non_finite", text.replace('"max_attempts":1', '"max_attempts":1e400')),
        ]
        for code, t in cases:
            self.assertNotEqual(t, text, "the mutation applied")
            r = verify_execution_grant(self.from_text(t), {"public_key": self.pk, "expected_kid": None},
                                       {"intended": {"executor_id": "exec-b"}})
            self.assertEqual((r["valid"], r["status"], r.get("reason")), (False, "MALFORMED", code), t[:60])
            self.assertNotIn("payload", r)

    def test_not_json_and_nan_keep_bad_json(self):
        import base64
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
        for t in ("this is not json", '{"v":"cr.exec.v2","max_attempts":NaN}'):
            r = verify_execution_grant(b64(t.encode()) + "." + b64(b"\0" * 64), {"public_key": self.pk, "expected_kid": None})
            self.assertEqual((r["status"], r.get("reason")), ("MALFORMED", "bad_json"), t)

    def test_v1_lone_surrogate_is_a_verdict_not_a_crash(self):
        import base64
        from pathlib import Path
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        doc = json.loads(Path(__file__).with_name("grant-vectors.json").read_text())
        seg, sig = next(v for v in doc["vectors"] if v["name"] == "EG-VALID")["token"].split(".")
        raw = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode("utf-8")
        mutated = raw.replace('"operation":"merge"', '"operation":"merge\\ud800"')
        self.assertNotEqual(mutated, raw)
        tok = base64.urlsafe_b64encode(mutated.encode()).rstrip(b"=").decode() + "." + sig
        ctx = {"public_key": load_pem_public_key(doc["public_key_pem"].encode()), "expected_kid": doc["kid"]}
        r = verify_execution_grant(tok, ctx)
        self.assertEqual((r["status"], r.get("reason")), ("INVALID_SIGNATURE", "signature_mismatch"))

    def test_writer_escapes_a_lone_surrogate_like_json_stringify(self):
        from verify_grant import dumps_like_js
        self.assertEqual(dumps_like_js({"a": "t\ud800", "b": "caf\u00e9"}), '{"a":"t\\ud800","b":"caf\u00e9"}')


if __name__ == "__main__":
    unittest.main()
