"""
contract_guard: a zero-config decorator that wires the full reference loop
around any agent tool.

On each call it does one well-known fetch, validates the bundle against the
published schema, runs verify_bundle (signature, hash pin, monotonic version,
TTL), and gates on the verdict. The wrapped tool body runs ONLY on allow.

It is framework-agnostic: wrap any callable. For LangGraph or LangChain, stack
it under the framework tool decorator.

    @contract_guard(base_url=URL, trusted_key=PUBKEY)
    def get_order_status(order_id): ...

A real implementation caches the contract by content_hash and revalidates only
the verdict in steady state. This minimal version refetches the small
well-known document each call to stay easy to read.
"""

import functools
import time

from coderifts_verify import verify_bundle
from schema_validate import validate_bundle_schema
from fetcher import fetch


class ContractGuardError(Exception):
    """Verification failed (schema, signature, hash pin, freshness, rollback)."""


class ContractGuardBlocked(Exception):
    """Verdict was BLOCK. The tool body did not run."""


class ContractGuardHold(Exception):
    """Verdict was REQUIRE_APPROVAL. The tool body did not run, escalate."""


def contract_guard(base_url, trusted_key, expected_ref="refs/heads/main", clock=time.time):
    state = {"last_seen": -1}

    def decorator(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            bundle, contract_bytes = fetch(base_url)
            errs = validate_bundle_schema(bundle)
            if errs:
                raise ContractGuardError("schema: " + errs[0])
            res = verify_bundle(bundle, contract_bytes, trusted_key, expected_ref,
                                state["last_seen"], int(clock()))
            if not res.ok:
                raise ContractGuardError(res.reason)
            state["last_seen"] = res.new_last_seen
            if res.action == "deny":
                raise ContractGuardBlocked(res.verdict)
            if res.action == "hold":
                raise ContractGuardHold(res.verdict)
            return fn(*args, **kwargs)

        return wrapped

    return decorator
