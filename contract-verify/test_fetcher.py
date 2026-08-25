"""
Fetcher tests: both well-known envelope forms resolve to the same bytes.

    python3 -m unittest test_fetcher -v
"""

import json
import os
import tempfile
import unittest

import _ed25519 as ed
from issuer import build_signed_bundle
from demo_loop import serve
from fetcher import fetch

CONTRACT = '{"openapi":"3.0.0"}'
NOW = 1_000_000


def write(root, name, text):
    with open(os.path.join(root, name), "w", encoding="utf-8") as f:
        f.write(text)


class FetcherTests(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk = ed.keypair(b"\x07" * 32)
        self.root = tempfile.mkdtemp(prefix="wk_f_")
        os.makedirs(os.path.join(self.root, ".well-known"))
        self.httpd, self.base = serve(self.root)
        self.bundle = build_signed_bundle(CONTRACT.encode(), "PASS", 7, self.sk, self.pk,
                                          issued_at=NOW, ttl_seconds=300)

    def tearDown(self):
        self.httpd.shutdown()

    def test_inline_contract(self):
        write(self.root, ".well-known/contract",
              json.dumps({"bundle": self.bundle, "contract": CONTRACT}))
        bundle, contract_bytes = fetch(self.base)
        self.assertEqual(bundle["version"], 7)
        self.assertEqual(contract_bytes, CONTRACT.encode("utf-8"))

    def test_contract_url(self):
        write(self.root, "spec.json", CONTRACT)
        write(self.root, ".well-known/contract",
              json.dumps({"bundle": self.bundle, "contract_url": "/spec.json"}))
        bundle, contract_bytes = fetch(self.base)
        self.assertEqual(bundle["version"], 7)
        self.assertEqual(contract_bytes, CONTRACT.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
