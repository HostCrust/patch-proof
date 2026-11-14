"""Inventory parsing, sanitising and the collector script."""

import hashlib
import shutil
import subprocess
import unittest
from pathlib import Path

from hcproof.inventory import InventoryError, ecosystem_for, parse_inventory, sanitise

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"


class TestEcosystem(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(ecosystem_for("debian", "12")[2], "Debian:12")
        self.assertEqual(ecosystem_for("debian", "11")[2], "Debian:11")
        self.assertEqual(ecosystem_for("ubuntu", "24.04")[2], "Ubuntu:24.04:LTS")
        self.assertEqual(ecosystem_for("ubuntu", "20.04")[2], "Ubuntu:20.04:LTS")
        self.assertEqual(ecosystem_for("ubuntu", "24.10")[2], "Ubuntu:24.10")
        self.assertEqual(ecosystem_for("almalinux", "9.4")[2], "AlmaLinux:9")
        self.assertEqual(ecosystem_for("rocky", "8.10")[2], "Rocky Linux:8")
        with self.assertRaises(InventoryError):
            ecosystem_for("arch", "rolling")
        with self.assertRaises(InventoryError):
            ecosystem_for("debian", "trixie/sid")


class TestCollectorFixtures(unittest.TestCase):
    def test_ubuntu_vm(self):
        data = (FIXTURES / "ubuntu-24.04-vm.txt").read_bytes()
        inv = parse_inventory(data)
        self.assertEqual(inv.ecosystem, "Ubuntu:24.04:LTS")
        self.assertEqual(inv.scheme, "dpkg")
        self.assertEqual(inv.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(inv.kernel_release, "6.8.0-31-generic")
        self.assertIn("6.8.0-31.31", inv.kernel_signature)
        self.assertFalse(inv.reboot_required)
        ssh = next(p for p in inv.packages if p.name == "openssh-server")
        self.assertEqual((ssh.source, ssh.source_version), ("openssh", "1:9.6p1-3ubuntu13.20"))
        self.assertGreater(len(inv.installed_packages), 600)

    def test_debian_synthetic(self):
        inv = parse_inventory((FIXTURES / "debian-12-synthetic.txt").read_bytes())
        self.assertEqual(inv.ecosystem, "Debian:12")
        self.assertTrue(inv.reboot_required)
        self.assertEqual(inv.reboot_packages, ["linux-image-6.1.0-54-amd64"])
        self.assertEqual(inv.kernel_images, ["6.1.0-26-amd64", "6.1.0-54-amd64"])
        # a removed kernel with its config files left is not installed
        old = [p for p in inv.packages if p.name == "linux-image-6.1.0-25-amd64"]
        self.assertEqual(len(old), 1)
        self.assertFalse(old[0].installed)
        php = next(p for p in inv.packages if p.name == "php8.2-common")
        self.assertEqual(php.source, "php8.2")
        self.assertTrue(php.source_version.startswith("8.2.29-1+0~2025"))
        img = next(p for p in inv.packages if p.name == "linux-image-6.1.0-26-amd64")
        self.assertEqual((img.source, img.source_version), ("linux-signed-amd64", "6.1.112+1"))

    def test_rpm_collector_output(self):
        text = (
            "# hcproof-collector 1\n## os-release\nID=\"almalinux\"\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"AlmaLinux 9.4\"\n"
            "## kernel\nrelease=5.14.0-427.13.1.el9_4.x86_64\n## reboot-required\nflag=no\n## packages\nformat=rpm\n"
            "openssh\t(none)\t8.7p1\t38.el9_4.1\tx86_64\topenssh-8.7p1-38.el9_4.1.src.rpm\tAlmaLinux\n"
            "openssl\t1\t3.0.7\t27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\tAlmaLinux\n"
            "gpg-pubkey\t(none)\tabc\tdef\t(none)\t(none)\t(none)\n## end\n"
        )
        inv = parse_inventory(text.encode())
        self.assertEqual(inv.ecosystem, "AlmaLinux:9")
        self.assertEqual(inv.scheme, "rpm")
        names = {p.name: p for p in inv.packages}
        self.assertNotIn("gpg-pubkey", names)
        self.assertEqual(names["openssh"].version, "0:8.7p1-38.el9_4.1")
        self.assertEqual(names["openssl"].version, "1:3.0.7-27.el9")
        self.assertEqual(names["openssl"].source_version, "1:3.0.7-27.el9")
        self.assertEqual(names["openssh"].vendor, "AlmaLinux")

    def test_truncated_input_is_rejected(self):
        with self.assertRaises(InventoryError):
            parse_inventory(b"# hcproof-collector 1\n## os-release\nID=ubuntu\nVERSION_ID=\"24.04\"\n")


class TestDegraded(unittest.TestCase):
    def test_dpkg_l(self):
        text = (
            "Desired=Unknown/Install/Remove/Purge/Hold\n||/ Name Version Architecture Description\n"
            "+++-====-====-====-====\n"
            "ii  openssh-server  1:9.6p1-3ubuntu13.5  amd64  secure shell (SSH) server\n"
            "ii  libc6:amd64     2.39-0ubuntu8.3      amd64  GNU C Library\n"
            "rc  oldpkg          1.0-1                amd64  removed\n"
        )
        inv = parse_inventory(text.encode(), "ubuntu:24.04")
        self.assertTrue(inv.degraded)
        self.assertEqual(inv.ecosystem, "Ubuntu:24.04:LTS")
        names = {p.name: p for p in inv.packages}
        self.assertEqual(names["libc6"].version, "2.39-0ubuntu8.3")
        self.assertFalse(names["oldpkg"].installed)

    def test_rpm_qa(self):
        text = "openssh-8.7p1-38.el9_4.1.x86_64\nkernel-core-5.14.0-427.13.1.el9_4.x86_64\ngpg-pubkey-abc-def\n"
        inv = parse_inventory(text.encode(), "rocky:9")
        names = {p.name: p for p in inv.packages}
        self.assertEqual(names["openssh"].version, "8.7p1-38.el9_4.1")
        self.assertEqual(names["kernel-core"].version, "5.14.0-427.13.1.el9_4")
        self.assertFalse(inv.epoch_known)

    def test_needs_os(self):
        with self.assertRaises(InventoryError):
            parse_inventory(b"ii  bash 5.2-1 amd64 shell\n")


class TestSanitise(unittest.TestCase):
    def test_drops_unknown_and_addresses(self):
        text = (
            "# hcproof-collector 1\n## os-release\nID=debian\nVERSION_ID=\"12\"\nHOME_URL=\"https://x\"\n"
            "BUILD_ID=\"host-10.1.2.3\"\nPRETTY_NAME=\"Debian 10.1.2.3\"\n"
            "## secret\nhostname=web01\n## kernel\nrelease=6.1.0-26-amd64\nnodename=web01\n"
            "## packages\nformat=dpkg\ninstall ok installed\tfoo\t1.2.3.4-1\tamd64\t\n## end\n"
        )
        out = sanitise(text)
        self.assertNotIn("web01", out)
        self.assertNotIn("HOME_URL", out)
        self.assertNotIn("BUILD_ID", out)
        self.assertNotIn("10.1.2.3", out.split("## packages")[0])
        self.assertIn("foo\t1.2.3.4-1", out)  # package versions are kept as is
        parse_inventory(out.encode())

    def test_fixtures_are_sanitised(self):
        for f in FIXTURES.glob("*.txt"):
            text = f.read_text()
            self.assertEqual(sanitise(text), text, f"{f.name} is not in sanitised form")


class TestCollectorScript(unittest.TestCase):
    def test_packaged_copy_is_identical(self):
        self.assertEqual((ROOT / "collect.sh").read_bytes(), (ROOT / "hcproof" / "collect.sh").read_bytes())

    def test_posix_syntax(self):
        sh = shutil.which("sh")
        if not sh:
            self.skipTest("no sh")
        subprocess.run([sh, "-n", str(ROOT / "collect.sh")], check=True)

    def test_short_and_read_only(self):
        text = (ROOT / "collect.sh").read_text()
        self.assertLess(len(text.splitlines()), 60)
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        for forbidden in ("curl", "wget", "hostname", "ip addr", "ifconfig", "rm ", "> /", "sudo", "apt-get", "dnf ", "yum "):
            self.assertNotIn(forbidden, code)

    def test_runs_locally(self):
        sh = shutil.which("sh")
        if not sh:
            self.skipTest("no sh")
        out = subprocess.run([sh, str(ROOT / "collect.sh")], capture_output=True, text=True, check=True).stdout
        self.assertTrue(out.startswith("# hcproof-collector 1"))
        self.assertIn("## packages", out)
        self.assertTrue(out.rstrip().endswith("## end"))


if __name__ == "__main__":
    unittest.main()
