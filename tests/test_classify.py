"""Classification rules on small, hand-written OSV data."""

import tempfile
import unittest
from pathlib import Path

from hcproof.classify import classify
from hcproof.inventory import parse_inventory
from hcproof.report import render_html, to_json

from .helpers import NOFIX, collector, dpkg_row, fixed, make_index, rec

U = "Ubuntu:24.04:LTS"
UPRO = "Ubuntu:Pro:24.04:LTS"
D = "Debian:12"
A = "AlmaLinux:9"

UBUNTU_RECORDS = [
    rec("UBUNTU-CVE-2024-0001", [(U, "openssh", fixed("1:9.6p1-3ubuntu13.3"), ["1:9.6p1-3ubuntu1", "1:9.6p1-3ubuntu13"])],
        upstream=["CVE-2024-0001"], related=["USN-9001-1"],
        severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}, {"type": "Ubuntu", "score": "high"}]),
    rec("UBUNTU-CVE-2023-0002", [(U, "openssh", fixed("1:9.6p1-3ubuntu1"), ["1:9.4p1-1ubuntu1"])], upstream=["CVE-2023-0002"]),
    rec("UBUNTU-CVE-2025-0003", [(U, "openssh", NOFIX, ["1:9.6p1-3ubuntu13.5"])], upstream=["CVE-2025-0003"],
        severity=[{"type": "Ubuntu", "score": "negligible"}]),
    rec("UBUNTU-CVE-2024-0004", [(U, "openssh", [{"introduced": "1:9.7p1-1"}, {"fixed": "1:9.7p1-2"}])], upstream=["CVE-2024-0004"]),
    rec("UBUNTU-CVE-2024-0005", [(U, "ffmpeg", NOFIX), (UPRO, "ffmpeg", fixed("7:6.1.1-3ubuntu5+esm1"))], upstream=["CVE-2024-0005"]),
    rec("UBUNTU-CVE-2024-0006", [(U, "linux", fixed("6.8.0-45.45"), ["6.8.0-31.31"])], upstream=["CVE-2024-0006"],
        details="In the Linux kernel, the following vulnerability has been resolved: netfilter: fix a thing. More text."),
    rec("UBUNTU-CVE-2024-0007", [(U, "linux", fixed("6.8.0-50.50"), ["6.8.0-31.31"])], upstream=["CVE-2024-0007"]),
    rec("UBUNTU-CVE-2024-0008", [(U, "linux", fixed("6.8.0-20.20"), ["6.8.0-11.11"])], upstream=["CVE-2024-0008"]),
    rec("UBUNTU-CVE-2024-0009", [(U, "linux", NOFIX)], upstream=["CVE-2024-0009"]),
    rec("UBUNTU-CVE-2024-0010", [(U, "nginx", fixed("1.24.0-2ubuntu7.1"))], upstream=["CVE-2024-0010"]),
    rec("USN-9001-1", [(U, "openssh", fixed("1:9.6p1-3ubuntu13.3"))], upstream=["CVE-2024-0001"]),
]

UBUNTU_INVENTORY = [
    dpkg_row("openssh-server", "1:9.6p1-3ubuntu13.5", "openssh"),
    dpkg_row("openssh-client", "1:9.6p1-3ubuntu13.5", "openssh"),
    dpkg_row("libavcodec60", "7:6.1.1-3ubuntu5", "ffmpeg"),
    dpkg_row("nginx", "1.26.2-1~noble"),
    dpkg_row("linux-image-6.8.0-31-generic", "6.8.0-31.31", "linux-signed"),
    dpkg_row("linux-modules-6.8.0-31-generic", "6.8.0-31.31", "linux"),
    dpkg_row("linux-image-6.8.0-48-generic", "6.8.0-48.48", "linux-signed"),
    dpkg_row("linux-modules-6.8.0-48-generic", "6.8.0-48.48", "linux"),
    dpkg_row("linux-libc-dev", "6.8.0-60.60", "linux"),
    dpkg_row("linux-generic", "6.8.0-48.48", "linux-meta"),
    dpkg_row("linux-image-6.8.0-20-generic", "6.8.0-20.20", "linux-signed", status="deinstall ok config-files"),
]


def by_key(result):
    return {(f.package, f.key): f for f in result.findings}


class TestUbuntu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.index = make_index(Path(cls.tmp.name), "Ubuntu", UBUNTU_RECORDS, [U])
        data = collector("ubuntu", "24.04", UBUNTU_INVENTORY,
                         kernel={"release": "6.8.0-31-generic", "signature": "Ubuntu 6.8.0-31.31-generic 6.8.1"},
                         reboot=True, reboot_pkgs=["linux-image-6.8.0-48-generic"])
        cls.inv = parse_inventory(data)
        cls.result = classify(cls.inv, cls.index)
        cls.f = by_key(cls.result)

    @classmethod
    def tearDownClass(cls):
        cls.index.close()
        cls.tmp.cleanup()

    def test_backport(self):
        f = self.f[("openssh", "CVE-2024-0001")]
        self.assertEqual(f.cls, "backport")
        self.assertEqual(f.fixed, "1:9.6p1-3ubuntu13.3")
        self.assertEqual(f.backport_of, "1:9.6p1-3ubuntu1")
        self.assertEqual(f.severity, "Ubuntu: high · CVSS 8.1")
        self.assertEqual(f.url, "https://ubuntu.com/security/CVE-2024-0001")
        self.assertIn("USN-9001-1", f.ids)
        self.assertEqual(f.binaries, ["openssh-client", "openssh-server"])

    def test_usn_is_not_double_counted(self):
        self.assertEqual([k for (p, k) in self.f if k == "CVE-2024-0001"], ["CVE-2024-0001"])

    def test_new_upstream_fix_is_normal(self):
        f = self.f[("openssh", "CVE-2023-0002")]
        self.assertEqual(f.cls, "fixed")

    def test_nofix(self):
        f = self.f[("openssh", "CVE-2025-0003")]
        self.assertEqual(f.cls, "nofix")
        self.assertEqual(f.fixed, "")
        self.assertEqual(f.severity, "Ubuntu: negligible")

    def test_not_introduced(self):
        self.assertNotIn(("openssh", "CVE-2024-0004"), self.f)

    def test_ubuntu_pro_fix(self):
        f = self.f[("ffmpeg", "CVE-2024-0005")]
        self.assertEqual(f.cls, "open")
        self.assertEqual(f.fixed, "7:6.1.1-3ubuntu5+esm1")
        self.assertTrue(any("Ubuntu Pro" in n for n in f.notes))

    def test_kernel_not_running(self):
        f = self.f[("linux", "CVE-2024-0006")]
        self.assertEqual(f.cls, "notrunning")
        self.assertEqual(f.running, "6.8.0-31.31")
        self.assertEqual(f.installed, "6.8.0-48.48")
        self.assertTrue(f.summary.startswith("netfilter: fix a thing."))

    def test_kernel_open_on_both(self):
        f = self.f[("linux", "CVE-2024-0007")]
        self.assertEqual(f.cls, "open")
        self.assertTrue(any("not fixed either" in n for n in f.notes))

    def test_kernel_backport_and_nofix(self):
        self.assertEqual(self.f[("linux", "CVE-2024-0008")].cls, "backport")
        self.assertEqual(self.f[("linux", "CVE-2024-0009")].cls, "nofix")

    def test_kernel_packages_not_reported_separately(self):
        self.assertFalse(any(f.package in ("linux-meta", "linux-signed") for f in self.result.findings))
        self.assertEqual(sum(1 for f in self.result.findings if f.key == "CVE-2024-0006"), 1)
        self.assertEqual(self.result.kernel.newest_version, "6.8.0-48.48")

    def test_third_party_not_assessed(self):
        self.assertNotIn(("nginx", "CVE-2024-0010"), self.f)
        names = {s.name for s in self.result.third_party}
        self.assertIn("nginx", names)
        self.assertIn("nginx", self.result.third_party_with_data)

    def test_counts(self):
        self.assertEqual(self.result.count("open"), (2, 2))
        self.assertEqual(self.result.count("notrunning"), (1, 1))
        self.assertEqual(self.result.count("backport"), (2, 2))

    def test_html_is_self_contained(self):
        html = render_html(self.result, "test <host>")
        self.assertIn("test &lt;host&gt;", html)
        self.assertNotIn("<host>", html)
        self.assertIn(self.inv.sha256, html)
        self.assertIn("hostcrust.com", html)
        self.assertIn("reboot-required flag is set", html)
        for bad in ("<script src", "<link ", "@import", "url(http"):
            self.assertNotIn(bad, html)
        self.assertIn("default-src 'none'", html)
        data = to_json(self.result, "x")
        self.assertEqual(data["counts"]["open"]["ids"], 2)


DEBIAN_RECORDS = [
    rec("DEBIAN-CVE-2024-1000", [(D, "openssh", fixed("1:9.2p1-2+deb12u3"), ["1:9.2p1-2"], {"urgency": "low"})], upstream=["CVE-2024-1000"]),
    rec("DSA-5724-1", [(D, "openssh", fixed("1:9.2p1-2+deb12u3"))], upstream=["CVE-2024-1000", "DEBIAN-CVE-2024-1000"],
        summary="openssh - security update"),
    rec("DEBIAN-CVE-2024-1001", [(D, "oldlib", NOFIX, [], {"urgency": "end-of-life"})], upstream=["CVE-2024-1001"]),
    rec("DEBIAN-CVE-2024-1002", [(D, "linux", fixed("6.1.115-1"), ["6.1.112-1"])], upstream=["CVE-2024-1002"]),
    rec("DEBIAN-CVE-2024-1003", [(D, "foo", [{"introduced": "0"}, {"fixed": "1.0-2"}, {"introduced": "1.1-1"}, {"fixed": "1.1-3"}])],
        upstream=["CVE-2024-1003"]),
    rec("DLA-0001-1", [(D, "bar", fixed("2.0-1+deb12u1"))], upstream=["CVE-2024-2000"]),
    rec("DLA-0002-1", [(D, "bar", fixed("2.0-1+deb12u3"))], upstream=["CVE-2024-2000"]),
    rec("DEBIAN-CVE-2024-1004", [(D, "binnmu", fixed("1.0-1+deb12u1"), ["1.0-1"])], upstream=["CVE-2024-1004"]),
]

DEBIAN_INVENTORY = [
    dpkg_row("openssh-server", "1:9.2p1-2+deb12u3", "openssh"),
    dpkg_row("oldlib1", "0.9-1", "oldlib"),
    dpkg_row("linux-image-6.1.0-26-amd64", "6.1.112-1", "linux-signed-amd64 (6.1.112+1)"),
    dpkg_row("linux-headers-6.1.0-26-common", "6.1.112-1", "linux", arch="all"),
    dpkg_row("linux-libc-dev", "6.1.119-1", "linux"),
    dpkg_row("libfoo1", "1.1-2", "foo"),
    dpkg_row("bar", "2.0-1+deb12u2"),
    dpkg_row("binnmu-bin", "1.0-1+deb12u1+b1", "binnmu (1.0-1+deb12u1)"),
]


class TestDebian(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.index = make_index(Path(cls.tmp.name), "Debian", DEBIAN_RECORDS, [D])
        data = collector("debian", "12", DEBIAN_INVENTORY,
                         kernel={"release": "6.1.0-26-amd64", "build": "#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)"})
        cls.result = classify(parse_inventory(data), cls.index)
        cls.f = by_key(cls.result)

    @classmethod
    def tearDownClass(cls):
        cls.index.close()
        cls.tmp.cleanup()

    def test_backport_with_advisory_ids(self):
        f = self.f[("openssh", "CVE-2024-1000")]
        self.assertEqual(f.cls, "backport")
        self.assertEqual(f.severity, "Debian: low")
        self.assertIn("DSA-5724-1", f.ids)
        self.assertEqual(f.url, "https://security-tracker.debian.org/tracker/CVE-2024-1000")
        self.assertEqual(sum(1 for f in self.result.findings if f.key == "CVE-2024-1000"), 1)

    def test_end_of_life_note(self):
        f = self.f[("oldlib", "CVE-2024-1001")]
        self.assertEqual(f.cls, "nofix")
        self.assertTrue(any("end-of-life" in n for n in f.notes))
        self.assertEqual(f.severity, "unrated")

    def test_debian_kernel(self):
        f = self.f[("linux", "CVE-2024-1002")]
        self.assertEqual(f.cls, "open")
        self.assertEqual(f.running, "6.1.112-1")
        self.assertEqual(self.result.kernel.source, "linux")

    def test_multi_range_affected_wins(self):
        self.assertEqual(self.f[("foo", "CVE-2024-1003")].cls, "open")
        self.assertEqual(self.f[("foo", "CVE-2024-1003")].fixed, "1.1-3")

    def test_advisories_fixed_wins(self):
        self.assertIn(self.f[("bar", "CVE-2024-2000")].cls, ("fixed", "backport"))

    def test_binnmu_uses_source_version(self):
        self.assertEqual(self.f[("binnmu", "CVE-2024-1004")].cls, "backport")


ALMA_RECORDS = [
    rec("ALSA-2024:1000", [(A, "openssh", fixed("8.7p1-38.el9")), (A, "openssh-server", fixed("8.7p1-38.el9"))],
        upstream=["CVE-2023-3000"], summary="Moderate: openssh security update"),
    rec("ALSA-2024:4312", [(A, "openssh", fixed("8.7p1-38.el9_4.1")), (A, "openssh-server", fixed("8.7p1-38.el9_4.1"))],
        upstream=["CVE-2024-6387"], summary="Important: openssh security update"),
    rec("ALSA-2024:5000", [(A, "nodejs", fixed("1:20.12.2-2.module_el9.4.0+100+abcdef12"))], upstream=["CVE-2024-5000"],
        summary="Important: nodejs:20 security update"),
    rec("ALSA-2024:7000", [(A, "kernel", fixed("5.14.0-427.40.1.el9_4")), (A, "kernel-core", fixed("5.14.0-427.40.1.el9_4"))],
        upstream=["CVE-2024-7000", "CVE-2024-7001"], summary="Important: kernel security update"),
    rec("ALSA-2024:8000", [(A, "php", fixed("8.0.30-1.el9_2"))], upstream=["CVE-2024-8000"], summary="Low: php update"),
    rec("ALSA-2024:9000", [(A, "openssl", fixed("1:3.0.7-27.el9"))], upstream=["CVE-2024-9000"], summary="Moderate: openssl"),
    rec("ALBA-2024:1", [(A, "openssh", fixed("8.7p1-99.el9"))], summary="bug fix"),
]


def rpm_row(name, epoch, version, release, srpm, vendor="AlmaLinux"):
    return (name, epoch, version, release, "x86_64", srpm, vendor)


class TestAlma(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.index = make_index(Path(cls.tmp.name), "AlmaLinux", ALMA_RECORDS, [A])
        rows = [
            rpm_row("openssh", "(none)", "8.7p1", "38.el9_4.4", "openssh-8.7p1-38.el9_4.4.src.rpm"),
            rpm_row("openssh-server", "(none)", "8.7p1", "38.el9_4.4", "openssh-8.7p1-38.el9_4.4.src.rpm"),
            rpm_row("nodejs", "1", "18.19.0", "1.module_el9.3.0+50+12345678", "nodejs-18.19.0-1.module_el9.3.0+50+12345678.src.rpm"),
            rpm_row("kernel-core", "(none)", "5.14.0", "427.13.1.el9_4", "kernel-5.14.0-427.13.1.el9_4.src.rpm"),
            rpm_row("kernel-core", "(none)", "5.14.0", "427.40.1.el9_4", "kernel-5.14.0-427.40.1.el9_4.src.rpm"),
            rpm_row("kernel-headers", "(none)", "5.14.0", "427.40.1.el9_4", "kernel-5.14.0-427.40.1.el9_4.src.rpm"),
            rpm_row("php", "(none)", "8.0.20", "1.el9.remi", "php-8.0.20-1.el9.remi.src.rpm", vendor="Remi's RPM repository"),
            rpm_row("openssl", "1", "3.0.7", "25.el9", "openssl-3.0.7-25.el9.src.rpm"),
        ]
        data = collector("almalinux", "9.4", rows, kernel={"release": "5.14.0-427.13.1.el9_4.x86_64"}, fmt="rpm")
        cls.result = classify(parse_inventory(data), cls.index)
        cls.f = by_key(cls.result)

    @classmethod
    def tearDownClass(cls):
        cls.index.close()
        cls.tmp.cleanup()

    def test_backport_from_advisory_history(self):
        f = self.f[("openssh", "CVE-2024-6387")]
        self.assertEqual(f.cls, "backport")
        self.assertEqual(f.backport_of, "8.7p1-38.el9")
        self.assertEqual(f.severity, "AlmaLinux advisory: Important")
        self.assertIn("ALSA-2024:4312", f.ids)

    def test_bugfix_advisories_ignored(self):
        self.assertFalse(any("ALBA-2024:1" in f.ids for f in self.result.findings))

    def test_module_stream_mismatch_is_skipped(self):
        self.assertNotIn(("nodejs", "CVE-2024-5000"), self.f)

    def test_kernel_not_running(self):
        for cve in ("CVE-2024-7000", "CVE-2024-7001"):
            f = self.f[("kernel", cve)]
            self.assertEqual(f.cls, "notrunning")
            self.assertEqual(f.running, "0:5.14.0-427.13.1.el9_4")
        self.assertFalse(any(f.package == "kernel-headers" for f in self.result.findings))

    def test_vendor_third_party(self):
        self.assertIn("php", {s.name for s in self.result.third_party})
        self.assertNotIn(("php", "CVE-2024-8000"), self.f)

    def test_epoch(self):
        self.assertEqual(self.f[("openssl", "CVE-2024-9000")].cls, "open")

    def test_no_fix_data_note(self):
        self.assertTrue(any("released fixes" in w for w in self.result.warnings))


class TestDegradedRpm(unittest.TestCase):
    def test_epochless_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = make_index(Path(tmp), "AlmaLinux", ALMA_RECORDS, [A])
            try:
                inv = parse_inventory(b"openssl-3.0.7-28.el9.x86_64\nopenssh-8.7p1-38.el9.x86_64\n", "almalinux:9")
                f = by_key(classify(inv, index))
            finally:
                index.close()
        # Without epochs, 3.0.7-28 is not reported as older than 1:3.0.7-27.
        self.assertNotEqual(f[("openssl", "CVE-2024-9000")].cls, "open")
        self.assertEqual(f[("openssh", "CVE-2024-6387")].cls, "open")


if __name__ == "__main__":
    unittest.main()
