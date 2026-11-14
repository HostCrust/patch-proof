"""End-to-end: two inventories against a slice of real OSV data.

* ``ubuntu-24.04-vm.txt``: a real Ubuntu 24.04 VM inventory (collector output, sanitised),
  taken once on 14 Nov 2026 and frozen. User-space packages were current; the kernel was
  still the 24.04 release kernel 6.8.0-31. It does not describe any server running today.
* ``debian-12-synthetic.txt``: a small hand-written Debian 12 inventory with real Debian
  package versions, an older running kernel, a newer installed one, and two third-party builds.

The slice (tests/fixtures/osv-subset.json.gz) is cut from one OSV snapshot per family, so
results are stable. Rebuild it and tests/fixtures/expected.json with ``python -m tests.subset``
and ``python -m tests.test_e2e --update`` after a data refresh, then re-check by hand.

Items in HAND_CHECKED were compared against ubuntu.com/security and
security-tracker.debian.org on 14 Nov 2026; see VERIFICATION.md.
"""

import gzip
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

from hcproof.classify import CLASSES, classify
from hcproof.inventory import parse_inventory
from hcproof.report import render_html

from . import subset

FIXTURES = Path(__file__).parent / "fixtures"
EXPECTED = FIXTURES / "expected.json"
UBUNTU = "ubuntu-24.04-vm.txt"
DEBIAN = "debian-12-synthetic.txt"

# (fixture, package, CVE) -> (class, fixed version). Hand-checked against the distro tracker.
HAND_CHECKED = {
    # Ubuntu 24.04 (noble), ubuntu.com/security
    (UBUNTU, "linux", "CVE-2024-26952"): ("open", "6.8.0-35.35"),
    (UBUNTU, "python-pip", "CVE-2024-35195"): ("open", "24.0+dfsg-1ubuntu1.3+esm1"),
    (UBUNTU, "openssh", "CVE-2024-6387"): ("backport", "1:9.6p1-3ubuntu13.3"),
    (UBUNTU, "glibc", "CVE-2024-2961"): ("backport", "2.39-0ubuntu8.1"),
    (UBUNTU, "sudo", "CVE-2025-32463"): ("backport", "1.9.15p5-3ubuntu5.24.04.1"),
    (UBUNTU, "curl", "CVE-2024-7264"): ("backport", "8.5.0-2ubuntu10.2"),
    (UBUNTU, "requests", "CVE-2024-35195"): ("nofix", ""),
    (UBUNTU, "openssh", "CVE-2023-48795"): ("fixed", "1:9.6p1-3ubuntu1"),
    # Debian 12 (bookworm), security-tracker.debian.org
    (DEBIAN, "openssh", "CVE-2025-26465"): ("open", "1:9.2p1-2+deb12u5"),
    (DEBIAN, "glibc", "CVE-2025-4802"): ("open", "2.36-9+deb12u11"),
    (DEBIAN, "openssl", "CVE-2024-13176"): ("open", "3.0.16-1~deb12u1"),
    (DEBIAN, "sudo", "CVE-2025-32462"): ("open", "1.9.13p3-1+deb12u2"),
    (DEBIAN, "curl", "CVE-2024-9681"): ("open", "7.88.1-10+deb12u9"),
    (DEBIAN, "linux", "CVE-2026-31431"): ("notrunning", "6.1.170-1"),
    (DEBIAN, "openssh", "CVE-2024-6387"): ("backport", "1:9.2p1-2+deb12u3"),
    (DEBIAN, "openssh", "CVE-2023-48795"): ("backport", "1:9.2p1-2+deb12u2"),
    (DEBIAN, "glibc", "CVE-2023-4911"): ("backport", "2.36-9+deb12u3"),
    (DEBIAN, "glibc", "CVE-2024-2961"): ("backport", "2.36-9+deb12u6"),
    (DEBIAN, "curl", "CVE-2024-7264"): ("backport", "7.88.1-10+deb12u7"),
    (DEBIAN, "openssl", "CVE-2024-5535"): ("fixed", "3.0.15-1~deb12u1"),
    (DEBIAN, "openssh", "CVE-2020-15778"): ("nofix", ""),
}

# (fixture, CVE): the distro says this release was never affected, so nothing may be reported.
NOT_AFFECTED = [(DEBIAN, "CVE-2025-32463")]


def _run_all(index):
    out = {}
    for name in subset.INVENTORIES:
        inv = parse_inventory((FIXTURES / name).read_bytes())
        out[name] = classify(inv, index)
    return out


class TestFixtureInventories(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        with gzip.open(subset.SUBSET, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
        cls.index = subset.load(data, Path(cls.tmp.name) / "subset.sqlite")
        t0 = time.monotonic()
        cls.results = _run_all(cls.index)
        cls.seconds = time.monotonic() - t0
        cls.expected = json.loads(EXPECTED.read_text())

    @classmethod
    def tearDownClass(cls):
        cls.index.close()
        cls.tmp.cleanup()

    def test_counts_match_expected(self):
        for name, result in self.results.items():
            got = {cls: list(result.count(cls)) for cls in CLASSES}
            self.assertEqual(got, self.expected[name]["counts"], name)

    def test_hand_checked_items(self):
        for (name, pkg, cve), (cls, fixed) in HAND_CHECKED.items():
            with self.subTest(fixture=name, cve=cve):
                hits = [f for f in self.results[name].findings if f.package == pkg and f.key == cve]
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0].cls, cls)
                self.assertEqual(hits[0].fixed, fixed)

    def test_not_affected_is_not_reported(self):
        for name, cve in NOT_AFFECTED:
            self.assertFalse([f for f in self.results[name].findings if f.key == cve], cve)

    def test_kernel_state(self):
        vm = self.results[UBUNTU].kernel
        self.assertEqual((vm.running_version, vm.newest_version), ("6.8.0-31.31", "6.8.0-31.31"))
        deb = self.results[DEBIAN]
        self.assertEqual((deb.kernel.source, deb.kernel.running_version, deb.kernel.newest_version), ("linux", "6.1.112-1", "6.1.190-1"))
        self.assertTrue(deb.inventory.reboot_required)
        # Every kernel CVE that is open on the running 6.1.112-1 but fixed in 6.1.190-1 is "not running".
        self.assertFalse([f for f in deb.findings if f.package == "linux" and f.cls == "open"])
        self.assertTrue([f for f in deb.findings if f.package == "linux" and f.cls == "notrunning"])

    def test_third_party_builds_not_assessed(self):
        third = {s.name for s in self.results[DEBIAN].third_party}
        self.assertEqual(third, {"php8.2", "nginx"})
        claimed = {f.package for f in self.results[DEBIAN].findings}
        self.assertFalse(third & claimed)

    def test_every_open_claim_is_backed_by_a_fix(self):
        for result in self.results.values():
            for f in result.by_class("open") + result.by_class("notrunning"):
                self.assertTrue(f.fixed, f.key)
                self.assertTrue(f.url.startswith("https://"))

    def test_speed_and_html(self):
        self.assertLess(self.seconds, 10)
        for name, result in self.results.items():
            html = render_html(result, "fixture")
            self.assertIn(result.inventory.sha256, html)
            self.assertNotIn("<script src", html)
            self.assertNotIn("<link ", html)


def update_expected() -> None:
    with gzip.open(subset.SUBSET, "rt", encoding="utf-8") as fh:
        data = json.load(fh)
    with tempfile.TemporaryDirectory() as tmp:
        index = subset.load(data, Path(tmp) / "subset.sqlite")
        results = _run_all(index)
        index.close()
    out = {k: v for k, v in sorted(data["meta"].items()) if k.startswith("snapshot_utc")}
    for name, result in results.items():
        out[name] = {"counts": {cls: list(result.count(cls)) for cls in CLASSES}}
    EXPECTED.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    if "--update" in sys.argv:
        update_expected()
    else:
        unittest.main()
