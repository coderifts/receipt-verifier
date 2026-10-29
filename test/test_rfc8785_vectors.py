"""1.1.6 — verify.py canonical_json against test/vectors/rfc8785.json (stdlib unittest).

The vectors' expected values are verify.js canonicalJson's (RFC 8785). MEASURED in round 10b: verify.py
differed on 5 of 16 (code-point key order; Python float repr: 1e+20, 1e-07, -0.0, 100.0). Every vector is
checked here: the canonical string and the sha256 of its UTF-8 bytes.
"""
import hashlib
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from verify import canonical_json  # noqa: E402

with open(os.path.join(HERE, "vectors", "rfc8785.json"), encoding="utf-8") as fh:
    DOC = json.load(fh)


class TestRfc8785Vectors(unittest.TestCase):
    def test_all_vectors_present(self):
        self.assertEqual(len(DOC["vectors"]), 16)

    def test_every_vector_canonical_and_sha256(self):
        for v in DOC["vectors"]:
            with self.subTest(v["id"]):
                got = canonical_json(json.loads(v["input_json"]))
                self.assertEqual(got, v["canonical"])
                self.assertEqual(hashlib.sha256(got.encode("utf-8")).hexdigest(), v["sha256"])

    def test_the_file_records_full_agreement(self):
        cc = DOC["cross_check"]
        self.assertEqual((cc["agrees"], cc["of"], cc["differs"]), (16, 16, []))

    def test_number_forms(self):
        cases = [(1e21, "1e+21"), (1e20, "100000000000000000000"), (1e-7, "1e-7"), (1e-6, "0.000001"),
                 (-0.0, "0"), (100.0, "100"), (0.1, "0.1"), (-1.5e-7, "-1.5e-7"), (5e-324, "5e-324"),
                 (1.7976931348623157e308, "1.7976931348623157e+308"), (2 ** 53 + 1, "9007199254740992")]
        for x, want in cases:
            with self.subTest(x):
                self.assertEqual(canonical_json(x), want)

    def test_non_finite_is_refused(self):
        for x in (float("nan"), float("inf"), float("-inf"), 10 ** 400):
            with self.subTest(x):
                with self.assertRaises(ValueError):
                    canonical_json(x)


if __name__ == "__main__":
    unittest.main()
