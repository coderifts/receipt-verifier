"""
fetcher: the minimal reference fetch side of the loop.

It does one GET against a tool's well-known endpoint and returns the signed
bundle plus the contract bytes. Stdlib only (urllib), no external deps. This
pairs directly with verify_bundle in coderifts_verify.

Well-known envelope. The document carries the bundle plus the contract, and the
contract may be delivered either way:

    { "bundle": { ...signed bundle... }, "contract": "<contract text>" }
or
    { "bundle": { ...signed bundle... }, "contract_url": "<url>" }

Inline `contract` keeps the cold start to a single round trip for small specs.
`contract_url` (absolute, or relative to the well-known URL) suits large specs
served separately. The agent uses whichever is present. Either way the verify
side pins content_hash against sha256 of the returned contract bytes.
"""

import json
import urllib.parse
import urllib.request

WELL_KNOWN_PATH = "/.well-known/contract"


def fetch(base_url, timeout=5):
    """GET base_url + /.well-known/contract and return (bundle, contract_bytes)."""
    url = base_url.rstrip("/") + WELL_KNOWN_PATH
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        doc = json.loads(resp.read().decode("utf-8"))
    bundle = doc["bundle"]
    if "contract" in doc:
        contract_bytes = doc["contract"].encode("utf-8")
    elif "contract_url" in doc:
        c_url = urllib.parse.urljoin(url, doc["contract_url"])
        with urllib.request.urlopen(c_url, timeout=timeout) as r2:
            contract_bytes = r2.read()
    else:
        raise ValueError("well-known document has neither contract nor contract_url")
    return bundle, contract_bytes
