"""
coderifts_verify: the agent-side verify layer for the contract discovery and
attestation protocol.

This is the *protocol* verify side, not the guard. The guard that produces a
verdict (PASS / REQUIRE_APPROVAL / BLOCK) is a black box here. This module only
verifies a signed bundle and hands the verdict to a gate.

Pipeline (order matters):
    1. signature   verify the bundle signature against a trusted guard key
    2. hash pin    content_hash == sha256(contract bytes)
    3. freshness   ref matches, version >= last_seen (rollback), inside TTL
    4. gate        map the verdict to an action for the agent

A bundle is a small JSON object:
    {
      "ref": "refs/heads/main",
      "commit_sha": "<40 hex>",
      "content_hash": "sha256:<hex>",
      "issued_at": <unix seconds>,
      "ttl_seconds": <int>,
      "version": <monotonic int>,
      "verdict": "PASS" | "REQUIRE_APPROVAL" | "BLOCK",
      "key_id": "ed25519:<name>",
      "signature": "<hex>"
    }
The signature covers every field except "signature" itself.
"""

import hashlib
import json

import _ed25519 as ed

SIGNED_FIELDS = (
    "ref", "commit_sha", "content_hash", "issued_at",
    "ttl_seconds", "version", "verdict", "key_id",
)

VALID_VERDICTS = ("PASS", "REQUIRE_APPROVAL", "BLOCK")

# How the agent acts on each verdict. The verdict comes from the guard;
# the gate is the agent-side policy applied to it.
GATE = {
    "PASS": "allow",             # run the tool
    "REQUIRE_APPROVAL": "hold",  # do not run automatically, escalate
    "BLOCK": "deny",             # do not run
}


def content_hash(data):
    """Return the canonical content hash of contract bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_bytes(bundle):
    """Deterministic serialization of the signed fields (excludes signature)."""
    payload = {k: bundle[k] for k in SIGNED_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class VerifyResult(object):
    def __init__(self, ok, reason, verdict=None, action=None, new_last_seen=None):
        self.ok = ok
        self.reason = reason
        self.verdict = verdict
        self.action = action
        self.new_last_seen = new_last_seen

    def __repr__(self):
        return "VerifyResult(ok=%r, reason=%r, verdict=%r, action=%r)" % (
            self.ok, self.reason, self.verdict, self.action)


def verify_bundle(bundle, contract_bytes, trusted_key, expected_ref,
                  last_seen_version, now):
    """Verify a signed bundle for a given contract.

    trusted_key       : 32-byte Ed25519 public key the agent trusts for this repo
    expected_ref      : e.g. "refs/heads/main"
    last_seen_version : highest version this agent has accepted so far (-1 if none)
    now               : current unix time (seconds)

    Returns VerifyResult. On success, new_last_seen is the accepted version and
    action is the gate decision (allow / hold / deny).
    """
    # 0. shape
    for f in SIGNED_FIELDS + ("signature",):
        if f not in bundle:
            return VerifyResult(False, "missing field: %s" % f)
    if bundle["verdict"] not in VALID_VERDICTS:
        return VerifyResult(False, "unknown verdict: %s" % bundle["verdict"])

    # 1. signature
    try:
        sig = bytes.fromhex(bundle["signature"])
    except ValueError:
        return VerifyResult(False, "signature not hex")
    if not ed.verify(sig, canonical_bytes(bundle), trusted_key):
        return VerifyResult(False, "signature invalid")

    # 2. hash pin
    if bundle["content_hash"] != content_hash(contract_bytes):
        return VerifyResult(False, "hash pin mismatch")

    # 3. freshness
    if bundle["ref"] != expected_ref:
        return VerifyResult(False, "ref mismatch: %s" % bundle["ref"])
    if bundle["version"] < last_seen_version:
        return VerifyResult(False, "rollback: version %s < last seen %s"
                            % (bundle["version"], last_seen_version))
    if now > bundle["issued_at"] + bundle["ttl_seconds"]:
        return VerifyResult(False, "expired: now %s > issued_at+ttl %s"
                            % (now, bundle["issued_at"] + bundle["ttl_seconds"]))

    # 4. gate
    verdict = bundle["verdict"]
    return VerifyResult(True, "ok", verdict=verdict, action=GATE[verdict],
                        new_last_seen=bundle["version"])
