"""
Tests for the zero-config decorator.

Run:
    python3 -m unittest test_decorator -v
"""

import tempfile
import unittest

import _ed25519 as ed
from issuer import build_signed_bundle
from demo_loop import serve, write_well_known
from decorator import (contract_guard, ContractGuardBlocked,
                       ContractGuardHold, ContractGuardError)

REF = "refs/heads/main"
CONTRACT = '{"openapi":"3.0.0"}'
NOW = 1_000_000


class DecoratorTests(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk = ed.keypair(b"\x07" * 32)
        self.root = tempfile.mkdtemp(prefix="wk_t_")
        self.httpd, self.base = serve(self.root)
        self.ran = {"n": 0}

        @contract_guard(base_url=self.base, trusted_key=self.pk,
                        expected_ref=REF, clock=lambda: NOW)
        def tool():
            self.ran["n"] += 1
            return "ok"

        self.tool = tool

    def tearDown(self):
        self.httpd.shutdown()

    def publish(self, verdict, version, contract=CONTRACT, ttl=300, issued_at=NOW):
        b = build_signed_bundle(contract.encode(), verdict, version, self.sk, self.pk,
                                issued_at=issued_at, ttl_seconds=ttl)
        write_well_known(self.root, b, contract)

    def test_pass_runs_body(self):
        self.publish("PASS", 7)
        self.assertEqual(self.tool(), "ok")
        self.assertEqual(self.ran["n"], 1)

    def test_block_skips_body(self):
        self.publish("BLOCK", 7)
        with self.assertRaises(ContractGuardBlocked):
            self.tool()
        self.assertEqual(self.ran["n"], 0)

    def test_require_approval_holds(self):
        self.publish("REQUIRE_APPROVAL", 7)
        with self.assertRaises(ContractGuardHold):
            self.tool()
        self.assertEqual(self.ran["n"], 0)

    def test_tamper_skips_body(self):
        b = build_signed_bundle(CONTRACT.encode(), "PASS", 7, self.sk, self.pk,
                                issued_at=NOW, ttl_seconds=300)
        write_well_known(self.root, b, CONTRACT + " tampered")
        with self.assertRaises(ContractGuardError):
            self.tool()
        self.assertEqual(self.ran["n"], 0)

    def test_rollback_skips_body(self):
        self.publish("PASS", 9)
        self.assertEqual(self.tool(), "ok")      # advances last_seen to 9
        self.publish("PASS", 5)                  # stale replay
        with self.assertRaises(ContractGuardError):
            self.tool()
        self.assertEqual(self.ran["n"], 1)


if __name__ == "__main__":
    unittest.main()
