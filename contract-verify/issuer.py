"""
issuer: a test stand-in for the party that signs attestations.

In a real deployment this is the guard running in CI (keyless OIDC workload
identity, or a repo-anchored guard key). Here it is a local Ed25519 signer so
the example runs end to end with no external services.

The guard logic that decides PASS / REQUIRE_APPROVAL / BLOCK is NOT here. This
only packages a given verdict into a signed bundle.
"""

import _ed25519 as ed
from coderifts_verify import SIGNED_FIELDS, canonical_bytes, content_hash


def build_signed_bundle(contract_bytes, verdict, version, private_key, public_key,
                        ref="refs/heads/main",
                        commit_sha="9f2c1a7b3e5d4c6a8b0f1e2d3c4b5a69788776655",
                        issued_at=0, ttl_seconds=300, key_id="ed25519:guard-ci"):
    bundle = {
        "ref": ref,
        "commit_sha": commit_sha,
        "content_hash": content_hash(contract_bytes),
        "issued_at": issued_at,
        "ttl_seconds": ttl_seconds,
        "version": version,
        "verdict": verdict,
        "key_id": key_id,
    }
    sig = ed.sign(canonical_bytes(bundle), private_key, public_key)
    bundle["signature"] = sig.hex()
    # sanity: only the documented signed fields are covered
    assert set(SIGNED_FIELDS).issubset(bundle.keys())
    return bundle
