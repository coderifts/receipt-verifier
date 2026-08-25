"""
Zero-config decorator demo: the full reference loop around a real tool call.

A guarded tool runs only when the live contract verdict allows it. We publish
PASS (tool runs), then BLOCK (tool body never runs), then REQUIRE_APPROVAL
(held), then a tampered contract (rejected). A side-effect counter proves the
body ran only when it should.

Run:
    python3 demo_decorator.py
"""

import _ed25519 as ed
from issuer import build_signed_bundle
from demo_loop import serve, write_well_known
from decorator import (contract_guard, ContractGuardBlocked,
                       ContractGuardHold, ContractGuardError)
import tempfile

REF = "refs/heads/main"
CONTRACT = '{"openapi":"3.0.0","paths":{"/orders/{id}":{"get":{}}}}'
NOW = 1_000_000

calls = {"ran": 0}


def line(label, note):
    print("%-28s | %s" % (label, note))


def main():
    sk, pk = ed.keypair(b"\x07" * 32)
    root = tempfile.mkdtemp(prefix="wk_dec_")
    httpd, base = serve(root)

    @contract_guard(base_url=base, trusted_key=pk, expected_ref=REF, clock=lambda: NOW)
    def get_order_status(order_id):
        calls["ran"] += 1
        return "order %s: shipped" % order_id

    print("Zero-config decorator: guard runs before the tool body")
    print("-" * 70)
    try:
        # PASS: tool runs.
        write_well_known(root, build_signed_bundle(CONTRACT.encode(), "PASS", 7, sk, pk,
                         issued_at=NOW, ttl_seconds=300), CONTRACT)
        out = get_order_status("A1")
        line("PASS", "tool ran -> %r  (ran=%d)" % (out, calls["ran"]))
        assert out.endswith("shipped") and calls["ran"] == 1

        # BLOCK: body must NOT run.
        write_well_known(root, build_signed_bundle(CONTRACT.encode(), "BLOCK", 8, sk, pk,
                         issued_at=NOW, ttl_seconds=300), CONTRACT)
        try:
            get_order_status("A2")
            raise SystemExit("FAIL: BLOCK did not stop the call")
        except ContractGuardBlocked as e:
            line("BLOCK", "raised ContractGuardBlocked(%s), body skipped (ran=%d)" % (e, calls["ran"]))
        assert calls["ran"] == 1

        # REQUIRE_APPROVAL: held.
        write_well_known(root, build_signed_bundle(CONTRACT.encode(), "REQUIRE_APPROVAL", 9, sk, pk,
                         issued_at=NOW, ttl_seconds=300), CONTRACT)
        try:
            get_order_status("A3")
            raise SystemExit("FAIL: REQUIRE_APPROVAL did not hold")
        except ContractGuardHold as e:
            line("REQUIRE_APPROVAL", "raised ContractGuardHold(%s), body skipped (ran=%d)" % (e, calls["ran"]))
        assert calls["ran"] == 1

        # Tamper: served contract altered, signature over old hash.
        write_well_known(root, build_signed_bundle(CONTRACT.encode(), "PASS", 10, sk, pk,
                         issued_at=NOW, ttl_seconds=300), CONTRACT + " tampered")
        try:
            get_order_status("A4")
            raise SystemExit("FAIL: tamper not caught")
        except ContractGuardError as e:
            line("tampered contract", "raised ContractGuardError(%s), body skipped (ran=%d)" % (e, calls["ran"]))
        assert calls["ran"] == 1

        print("-" * 70)
        print("Body ran exactly once, only under PASS. Guard sat in front of every call.")
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
