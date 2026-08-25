"""
End-to-end demo of the verify side.

Run:
    python3 demo.py

It generates a guard keypair, issues signed bundles, and runs each through the
verify pipeline. The happy path passes; tamper, rollback, expiry, wrong-ref,
wrong-key, and a BLOCK verdict all behave as expected. Every scenario asserts
its outcome, so a clean run is also the test.
"""

import _ed25519 as ed
from coderifts_verify import verify_bundle
from issuer import build_signed_bundle

REF = "refs/heads/main"
SAMPLE_CONTRACT = b'{"openapi":"3.0.0","paths":{"/orders":{"get":{"responses":{"200":{}}}}}}'
NOW = 1_000_000  # fixed clock for a deterministic demo


def line(label, res):
    verdict = res.verdict if res.verdict else "-"
    action = res.action if res.action else "-"
    status = "ACCEPT" if res.ok else "REJECT"
    print("%-26s | %-6s | verdict=%-16s | action=%-5s | %s"
          % (label, status, verdict, action, res.reason))


def main():
    sk, pk = ed.keypair(b"\x07" * 32)          # the guard key the agent trusts
    other_sk, other_pk = ed.keypair(b"\x09" * 32)  # an untrusted key

    print("Contract discovery + attestation: verify side")
    print("guard key id: ed25519:guard-ci   trusted by the agent")
    print("-" * 92)

    # 1. Happy path: fresh PASS bundle, agent has seen nothing yet.
    good = build_signed_bundle(SAMPLE_CONTRACT, "PASS", version=7,
                               private_key=sk, public_key=pk,
                               issued_at=NOW, ttl_seconds=300)
    r = verify_bundle(good, SAMPLE_CONTRACT, pk, REF, last_seen_version=-1, now=NOW)
    line("fresh PASS", r)
    assert r.ok and r.action == "allow" and r.new_last_seen == 7

    # 2. Steady state: agent already at version 7, same bundle revalidates fast.
    r = verify_bundle(good, SAMPLE_CONTRACT, pk, REF, last_seen_version=7, now=NOW + 10)
    line("revalidate at v7", r)
    assert r.ok and r.action == "allow"

    # 3. BLOCK verdict: signed and fresh, but the gate denies the call.
    blocked = build_signed_bundle(SAMPLE_CONTRACT, "BLOCK", version=8,
                                  private_key=sk, public_key=pk,
                                  issued_at=NOW, ttl_seconds=300)
    r = verify_bundle(blocked, SAMPLE_CONTRACT, pk, REF, last_seen_version=7, now=NOW)
    line("fresh BLOCK", r)
    assert r.ok and r.action == "deny" and r.verdict == "BLOCK"

    # 4. REQUIRE_APPROVAL: valid, but held for escalation.
    appr = build_signed_bundle(SAMPLE_CONTRACT, "REQUIRE_APPROVAL", version=9,
                               private_key=sk, public_key=pk,
                               issued_at=NOW, ttl_seconds=300)
    r = verify_bundle(appr, SAMPLE_CONTRACT, pk, REF, last_seen_version=7, now=NOW)
    line("fresh REQUIRE_APPROVAL", r)
    assert r.ok and r.action == "hold"

    # 5. Tampered contract: signature is over the old hash, pin fails.
    r = verify_bundle(good, SAMPLE_CONTRACT + b" tampered", pk, REF,
                      last_seen_version=-1, now=NOW)
    line("tampered contract", r)
    assert not r.ok and "hash pin" in r.reason

    # 6. Rollback: an old version replayed after the agent moved on.
    old = build_signed_bundle(SAMPLE_CONTRACT, "PASS", version=5,
                              private_key=sk, public_key=pk,
                              issued_at=NOW, ttl_seconds=300)
    r = verify_bundle(old, SAMPLE_CONTRACT, pk, REF, last_seen_version=7, now=NOW)
    line("rollback to v5", r)
    assert not r.ok and "rollback" in r.reason

    # 7. Expired: outside the TTL window.
    r = verify_bundle(good, SAMPLE_CONTRACT, pk, REF, last_seen_version=-1,
                      now=NOW + 301)
    line("expired (past TTL)", r)
    assert not r.ok and "expired" in r.reason

    # 8. Wrong ref.
    branch = build_signed_bundle(SAMPLE_CONTRACT, "PASS", version=10,
                                 private_key=sk, public_key=pk,
                                 ref="refs/heads/dev", issued_at=NOW, ttl_seconds=300)
    r = verify_bundle(branch, SAMPLE_CONTRACT, pk, REF, last_seen_version=-1, now=NOW)
    line("wrong ref (dev)", r)
    assert not r.ok and "ref mismatch" in r.reason

    # 9. Untrusted signer: signed with a key the agent does not trust.
    forged = build_signed_bundle(SAMPLE_CONTRACT, "PASS", version=11,
                                 private_key=other_sk, public_key=other_pk,
                                 issued_at=NOW, ttl_seconds=300)
    r = verify_bundle(forged, SAMPLE_CONTRACT, pk, REF, last_seen_version=-1, now=NOW)
    line("untrusted signer", r)
    assert not r.ok and "signature invalid" in r.reason

    print("-" * 92)
    print("All scenarios behaved as expected.")


if __name__ == "__main__":
    main()
