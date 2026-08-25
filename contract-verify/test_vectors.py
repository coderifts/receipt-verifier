"""
Run the published conformance vectors as part of the test suite.

    python3 -m unittest test_vectors -v
"""

import unittest

from check_vectors import run


class VectorTests(unittest.TestCase):
    def test_all_vectors_pass(self):
        self.assertEqual(run(), 0)


if __name__ == "__main__":
    unittest.main()
