"""Version comparison against the shared vectors (tests/vectors/*.json).

The same vectors are meant for ports of the comparison code to other languages: every
implementation must agree on every line.
"""

import json
import unittest
from pathlib import Path

from hcproof.versions import (
    compare,
    dpkg_compare,
    dpkg_split,
    dpkg_upstream,
    rpm_compare,
    rpm_split,
    rpm_upstream,
    rpmvercmp,
)

VECTORS = Path(__file__).parent / "vectors"


def load(name):
    data = json.loads((VECTORS / f"{name}.json").read_text())
    assert data["scheme"] == name
    return data["vectors"]


class TestVectors(unittest.TestCase):
    def check(self, scheme, fn):
        vectors = load(scheme)
        self.assertGreaterEqual(len(vectors), 40)
        for v in vectors:
            with self.subTest(a=v["a"], b=v["b"]):
                self.assertEqual(fn(v["a"], v["b"]), v["cmp"], v.get("note"))
                self.assertEqual(fn(v["b"], v["a"]), -v["cmp"], "antisymmetry")
                self.assertEqual(fn(v["a"], v["a"]), 0, "reflexive")

    def test_dpkg_vectors(self):
        self.check("dpkg", dpkg_compare)

    def test_rpm_vectors(self):
        self.check("rpm", rpm_compare)

    def test_dispatch(self):
        self.assertEqual(compare("dpkg", "1.0~rc1", "1.0"), -1)
        self.assertEqual(compare("rpm", "1.0~rc1", "1.0"), -1)
        with self.assertRaises(ValueError):
            compare("apk", "1", "2")

    def test_transitive_sort(self):
        # Sorting with the comparator must give a consistent order.
        from functools import cmp_to_key

        versions = ["1.0~~", "1.0~~a", "1.0~", "1.0", "1.0a", "1.0+", "1:0.1", "1.0-1", "1.0.1"]
        ordered = sorted(versions, key=cmp_to_key(dpkg_compare))
        for x, y in zip(ordered, ordered[1:]):
            self.assertLessEqual(dpkg_compare(x, y), 0)


class TestSplit(unittest.TestCase):
    def test_dpkg_split(self):
        self.assertEqual(dpkg_split("1:9.6p1-3ubuntu13.5"), (1, "9.6p1", "3ubuntu13.5"))
        self.assertEqual(dpkg_split("2.36-9+deb12u7"), (0, "2.36", "9+deb12u7"))
        self.assertEqual(dpkg_split("1.2-3-4"), (0, "1.2-3", "4"))
        self.assertEqual(dpkg_split("20240318"), (0, "20240318", ""))

    def test_dpkg_upstream(self):
        self.assertEqual(dpkg_upstream("1:9.2p1-2+deb12u3"), "1:9.2p1")
        self.assertEqual(dpkg_upstream("6.8.0-149.149"), "0:6.8.0")
        self.assertEqual(dpkg_upstream("6.8.0-45.45~22.04.1"), "0:6.8.0")

    def test_rpm_split(self):
        self.assertEqual(rpm_split("0:8.7p1-38.el9_4.4"), (0, "8.7p1", "38.el9_4.4"))
        self.assertEqual(rpm_split("8.7p1-38.el9_4.1"), (0, "8.7p1", "38.el9_4.1"))
        self.assertEqual(rpm_split("1:3.0.7-27.el9"), (1, "3.0.7", "27.el9"))

    def test_rpm_upstream(self):
        self.assertEqual(rpm_upstream("5.14.0-427.13.1.el9_4"), "0:5.14.0")

    def test_rpmvercmp_basics(self):
        self.assertEqual(rpmvercmp("1.0", "1.0"), 0)
        self.assertEqual(rpmvercmp("el9", "el9_4"), -1)


if __name__ == "__main__":
    unittest.main()
