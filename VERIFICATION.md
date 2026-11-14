# Verification

How the results of HostCrust Patch Proof were checked by hand against the distributions' own trackers on 14 Nov 2026, and what was not checked.

## Method

1. **Collect.** An inventory comes from [`collect.sh`](collect.sh) (read-only), or is written by hand for the synthetic fixture.
2. **Report.** It runs against one recorded OSV.dev snapshot per distribution family.
3. **Spot-check.** For each result class, pick items and compare the report with the line for that release on the distribution's own tracker:
   - [ubuntu.com/security](https://ubuntu.com/security/cves), "Ubuntu 24.04 LTS (noble)"
   - [security-tracker.debian.org](https://security-tracker.debian.org/tracker/), "bookworm"
4. **Lock it in.** Every row below is asserted in [`tests/test_e2e.py`](tests/test_e2e.py) (`HAND_CHECKED` and `NOT_AFFECTED`). A code change that alters one of these verdicts fails the tests, which run on every push.

## Inputs

| | Ubuntu 24.04 VM | Debian 12 synthetic inventory |
|---|---|---|
| What it is | A real Ubuntu 24.04 cloud VM, collected once on 14 Nov 2026 and frozen. User-space packages were up to date from the standard Ubuntu archive; the only open non-kernel fixes needed Ubuntu Pro. It still ran the 24.04 release kernel 6.8.0-31, and no newer kernel was installed (`linux-generic` was at 6.8.0-31.31). This fixture describes no server running today | Written by hand to cover what the Ubuntu fixture does not (see [below](#how-the-synthetic-debian-12-inventory-was-made)): Debian's data, an older running kernel next to a newer installed one, the reboot flag, a removed kernel, and third-party builds |
| Fixture | [`tests/fixtures/ubuntu-24.04-vm.txt`](tests/fixtures/ubuntu-24.04-vm.txt) | [`tests/fixtures/debian-12-synthetic.txt`](tests/fixtures/debian-12-synthetic.txt) |
| Input SHA-256 | `2f50b209...9625534d` | `dc5a309e...e9d28bdb` |
| OS | Ubuntu 24.04.5 LTS | Debian GNU/Linux 12 (bookworm) |
| Installed packages | 690 | 16, plus one removed kernel with config files left |
| Running kernel | 6.8.0-31-generic (package 6.8.0-31.31) | 6.1.0-26-amd64 (package 6.1.112-1); 6.1.0-54-amd64 (6.1.190-1) installed; reboot-required flag set |
| Data | OSV Ubuntu snapshot 2026-11-14T07:03:07Z | OSV Debian snapshot 2026-11-14T11:02:45Z |
| Report | [`samples/ubuntu-24.04-vm.html`](samples/ubuntu-24.04-vm.html) | [`samples/debian-12-synthetic.html`](samples/debian-12-synthetic.html) |

**Sanitising the Ubuntu inventory.** `hc-proof sanitise` kept only the known os-release keys, the kernel lines, the reboot flag and the package table. The collector reads no hostname or IP address, so there were none to remove; the only change was dropping the os-release URL and logo lines.

## Results (distinct CVE IDs, packages)

| Class | Ubuntu 24.04 VM | Debian 12 synthetic |
|---|---|---|
| Patch available, not installed | 9,261 in 3 packages (9,257 of them the kernel; the other 4 need Ubuntu Pro) | 69 in 5 packages |
| Patched on disk, not running | 0 | 5,657 (kernel: running 6.1.112-1, installed 6.1.190-1) |
| No distro fix yet | 1,564 in 87 packages | 2,099 in 6 packages (1,994 of them the kernel) |
| Fixed by backport | 777 in 95 packages | 38 in 3 packages |
| Fixed, normal | 112 in 27 packages | 8,139 in 6 packages (7,563 of them the kernel) |
| Not assessed (third-party builds) | 0 | 2 source packages (deb.sury.org PHP, nginx.org) |

Debian's kernel fixes are mostly "fixed, normal" rather than "fixed by backport", because Debian 12 moves to new upstream 6.1.y stable releases (6.1.112, 6.1.170, ...). A backport, by this tool's rule, is a fix in a new distro revision of the same upstream version.

## Spot check: Ubuntu 24.04 against ubuntu.com/security (noble)

### Open (patch available, not installed)

| # | Package (installed) | CVE | Report says | Ubuntu tracker says (noble) | Match |
|---|---|---|---|---|---|
| 1 | linux (running 6.8.0-31.31) | [CVE-2024-26952](https://ubuntu.com/security/CVE-2024-26952) | Open, fixed in 6.8.0-35.35; Ubuntu: critical | Fixed in 6.8.0-35.35; priority Critical | Yes |
| 2 | python-pip 24.0+dfsg-1ubuntu1.3 | [CVE-2024-35195](https://ubuntu.com/security/CVE-2024-35195) | Open, fixed in 24.0+dfsg-1ubuntu1.3+esm1, "Fix available with Ubuntu Pro (ESM)" | Fixed in 24.0+dfsg-1ubuntu1.3+esm1, available with Ubuntu Pro via ESM Apps | Yes |

### Fixed by backport

For each one, the installed upstream version is older than the upstream release that fixed the issue. So a scanner that compares upstream version numbers reports it as vulnerable, though Ubuntu patched it in a distro revision.

| # | Package (installed) | CVE | Report says | Ubuntu tracker says (noble) | Upstream fix (what a version-string scanner checks) | Match |
|---|---|---|---|---|---|---|
| 1 | openssh 1:9.6p1-3ubuntu13.20 | [CVE-2024-6387](https://ubuntu.com/security/CVE-2024-6387) | Backport: fixed in 1:9.6p1-3ubuntu13.3; 1:9.6p1-3ubuntu1 was affected | Fixed in 1:9.6p1-3ubuntu13.3 | OpenSSH 9.8p1 (installed upstream 9.6p1) | Yes |
| 2 | glibc 2.39-0ubuntu8.12 | [CVE-2024-2961](https://ubuntu.com/security/CVE-2024-2961) | Backport: fixed in 2.39-0ubuntu8.1 | Fixed in 2.39-0ubuntu8.1 | affects "2.39 and older" (installed upstream 2.39) | Yes |
| 3 | sudo 1.9.15p5-3ubuntu5.24.04.4 | [CVE-2025-32463](https://ubuntu.com/security/CVE-2025-32463) | Backport: fixed in 1.9.15p5-3ubuntu5.24.04.1 | Fixed in 1.9.15p5-3ubuntu5.24.04.1 | "Sudo before 1.9.17p1" (installed upstream 1.9.15p5) | Yes |
| 4 | curl 8.5.0-2ubuntu10.16 | [CVE-2024-7264](https://ubuntu.com/security/CVE-2024-7264) | Backport: fixed in 8.5.0-2ubuntu10.2 | Fixed in 8.5.0-2ubuntu10.2 | curl 8.9.1 (installed upstream 8.5.0) | Yes |

### Other classes

| Package | CVE | Report says | Ubuntu tracker says (noble) | Match |
|---|---|---|---|---|
| requests 2.31.0+dfsg-1ubuntu1.2 | [CVE-2024-35195](https://ubuntu.com/security/CVE-2024-35195) | No distro fix yet | "Ignored (breaks users, requires source code updates)" | Yes. OSV does not carry Ubuntu's "ignored" reason, so the report cannot tell it apart from "deferred" |
| openssh 1:9.6p1-3ubuntu13.20 | [CVE-2023-48795](https://ubuntu.com/security/CVE-2023-48795) (Terrapin) | Fixed, normal: fixed in 1:9.6p1-3ubuntu1, a new upstream version (9.6) | Fixed in 1:9.6p1-3ubuntu1 | Yes. Not a backport: upstream 9.6 contains the fix |

**Ubuntu outcome:** 2 of 2 open items, 4 of 4 backport items and 2 of 2 other items match the Ubuntu tracker. Every non-kernel open item on this VM is a fix that Ubuntu ships only through Ubuntu Pro (ESM Apps); the VM was not attached to Pro, and the report labels these.

## Spot check: Debian 12 against security-tracker.debian.org (bookworm)

### Open, and patched on disk but not running

| # | Package (installed) | CVE | Report says | Debian tracker says (bookworm) | Match |
|---|---|---|---|---|---|
| 1 | openssh 1:9.2p1-2+deb12u3 | [CVE-2025-26465](https://security-tracker.debian.org/tracker/CVE-2025-26465) | Open, fixed in 1:9.2p1-2+deb12u5 | Fixed in 1:9.2p1-2+deb12u5 (DSA-5868-1) | Yes |
| 2 | glibc 2.36-9+deb12u7 | [CVE-2025-4802](https://security-tracker.debian.org/tracker/CVE-2025-4802) | Open, fixed in 2.36-9+deb12u11 | Fixed in 2.36-9+deb12u11; the tracker's own table lists 2.36-9+deb12u7 as vulnerable | Yes |
| 3 | openssl 3.0.15-1~deb12u1 | [CVE-2024-13176](https://security-tracker.debian.org/tracker/CVE-2024-13176) | Open, fixed in 3.0.16-1~deb12u1 | Fixed in 3.0.16-1~deb12u1 | Yes |
| 4 | sudo 1.9.13p3-1+deb12u1 | [CVE-2025-32462](https://security-tracker.debian.org/tracker/CVE-2025-32462) | Open, fixed in 1.9.13p3-1+deb12u2 | Fixed in 1.9.13p3-1+deb12u2 (DSA-5954-1) | Yes |
| 5 | curl 7.88.1-10+deb12u8 | [CVE-2024-9681](https://security-tracker.debian.org/tracker/CVE-2024-9681) | Open, fixed in 7.88.1-10+deb12u9 | Fixed in 7.88.1-10+deb12u9 | Yes |
| 6 | linux (running 6.1.112-1, installed 6.1.190-1) | [CVE-2026-31431](https://security-tracker.debian.org/tracker/CVE-2026-31431) ("Copy Fail") | Patched on disk, not running; fixed in 6.1.170-1 | Fixed in 6.1.170-1 (DSA-6243-1) | Yes |

### Fixed by backport

| # | Package (installed) | CVE | Report says | Debian tracker says (bookworm) | Upstream fix (what a version-string scanner checks) | Match |
|---|---|---|---|---|---|---|
| 1 | openssh 1:9.2p1-2+deb12u3 | [CVE-2024-6387](https://security-tracker.debian.org/tracker/CVE-2024-6387) | Backport: fixed in 1:9.2p1-2+deb12u3; 1:9.2p1-1 was affected | Fixed in 1:9.2p1-2+deb12u3 (DSA-5724-1) | OpenSSH 9.8p1 (`V_9_8_P1`; installed upstream 9.2p1) | Yes |
| 2 | openssh 1:9.2p1-2+deb12u3 | [CVE-2023-48795](https://security-tracker.debian.org/tracker/CVE-2023-48795) | Backport: fixed in 1:9.2p1-2+deb12u2 | Fixed in 1:9.2p1-2+deb12u2 | Debian unstable got the fix with OpenSSH 9.6p1 (installed upstream 9.2p1) | Yes |
| 3 | glibc 2.36-9+deb12u7 | [CVE-2023-4911](https://security-tracker.debian.org/tracker/CVE-2023-4911) ("Looney Tunables") | Backport: fixed in 2.36-9+deb12u3 | Fixed in 2.36-9+deb12u3 (DSA-5514-1) | Debian unstable got the fix in 2.37-12 (installed upstream 2.36) | Yes |
| 4 | glibc 2.36-9+deb12u7 | [CVE-2024-2961](https://security-tracker.debian.org/tracker/CVE-2024-2961) | Backport: fixed in 2.36-9+deb12u6 | Fixed in 2.36-9+deb12u6 (DSA-5673-1) | Debian unstable got the fix in 2.37-18 (installed upstream 2.36) | Yes |
| 5 | curl 7.88.1-10+deb12u8 | [CVE-2024-7264](https://security-tracker.debian.org/tracker/CVE-2024-7264) | Backport: fixed in 7.88.1-10+deb12u7 | Fixed in 7.88.1-10+deb12u7 | curl 8.9.1 (`curl-8_9_1`; installed upstream 7.88.1) | Yes |

### Other classes

| Package (installed) | CVE | Report says | Debian tracker says (bookworm) | Match |
|---|---|---|---|---|
| openssl 3.0.15-1~deb12u1 | [CVE-2024-5535](https://security-tracker.debian.org/tracker/CVE-2024-5535) | Fixed, normal: fixed in 3.0.15-1~deb12u1, a new upstream version | Fixed in 3.0.15-1~deb12u1 | Yes |
| openssh 1:9.2p1-2+deb12u3 | [CVE-2020-15778](https://security-tracker.debian.org/tracker/CVE-2020-15778) | No distro fix yet; Debian: unimportant | Unfixed; urgency "unimportant" | Yes |
| sudo 1.9.13p3-1+deb12u1 | [CVE-2025-32463](https://security-tracker.debian.org/tracker/CVE-2025-32463) | Not reported | bookworm "not affected (vulnerable code introduced later)" | Yes |
| php8.2, nginx (third-party builds) | — | Not assessed | — | By design: deb.sury.org and nginx.org builds are not described by Debian's data |

**Debian outcome:** 6 of 6 open or not-running items, 5 of 5 backport items and 3 of 3 other items match the Debian tracker. No false "you're vulnerable" claim was found in either spot check.

## How the synthetic Debian 12 inventory was made

The Ubuntu fixture can't test several things: a second distribution family, a kernel that is installed but not running, the reboot flag, a removed package, and third-party builds. So [`tests/fixtures/debian-12-synthetic.txt`](tests/fixtures/debian-12-synthetic.txt) was written by hand:

1. **Package versions** are real bookworm builds named in Debian's own data: for example `openssh 1:9.2p1-2+deb12u3`, `glibc 2.36-9+deb12u7` and `curl 7.88.1-10+deb12u8`.
2. **Kernel package names** were checked against [snapshot.debian.org](https://snapshot.debian.org/): `linux-image-6.1.0-25-amd64` is 6.1.106-3, `6.1.0-26-amd64` is 6.1.112-1 and `6.1.0-54-amd64` is 6.1.190-1. The `uname -v` line gives the running build as `Debian 6.1.112-1`.
3. **Third-party version strings** are synthetic, in the formats those repositories use: deb.sury.org's `+0~YYYYMMDD...+debian12~1.gbp...` and nginx.org's `~bookworm`.
4. **Expected results** were derived by running the tool on the OSV slice in [`tests/fixtures/osv-subset.json.gz`](tests/fixtures/osv-subset.json.gz). The counts are identical to a run against the full Debian 12 index of the same snapshot.
5. **Hand check:** every item above was compared with the "bookworm" line of the Debian tracker page on 14 Nov 2026.

## Version comparison

`tests/vectors/dpkg.json` (58 vectors) and `tests/vectors/rpm.json` (46 vectors) pass in both directions. During development they were also cross-checked against two independent implementations, installed in a throwaway virtualenv (they are not dependencies):

- All dpkg vectors agree with `python-debian` 1.1.1.
- All rpm vectors agree with `rpm-vercmp` 0.1.2, except the two caret (`^`) vectors, which that older port does not support. For those two, the expected values come from rpm's own test suite (`tests/rpmvercmp.at`).

## Not verified

- **No real Debian, AlmaLinux or Rocky Linux server** has been spot-checked; the only real inventory is Ubuntu 24.04. The AlmaLinux and Rocky Linux paths are covered by unit tests on hand-written OSV records ([`tests/test_classify.py`](tests/test_classify.py)), not by a real inventory or a tracker check.
- **No side-by-side run against other scanners.** The comparison table in the README cites each tool's own documentation and nothing else.
- **RPM minor-release streams.** When advisories fix the same CVE separately for several minor-release streams (for example AlmaLinux 9 `el9_7` and `el9_8` kernels), the tool compares against the lowest fixed version. An early build of the newer stream, made before that stream's fix, could then be shown as fixed. See [docs/cve-2026-31431.md](docs/cve-2026-31431.md) for a real case where this matters.

## After-update check: the Ubuntu 24.04 VM, 14 Nov 2026

The same VM was then updated and checked again:

- **Update:** `apt-get full-upgrade` (41 packages, including `linux-image-6.8.0-149-generic`), then a reboot. It now ran 6.8.0-149.
- **Re-run:** the collector and the report, with the same OSV snapshot.

| Class | Before (6.8.0-31) | After (6.8.0-149) |
|---|---|---|
| Patch available, not installed | 9,261 (9,257 kernel) | **4** (all need Ubuntu Pro) |
| Patched on disk, not running | 0 | 0 |
| Fixed by backport | 777 | 10,034 |
| No distro fix yet | 1,564 | 1,564 |
| Fixed, normal | 112 | 112 |

The 9,257 kernel CVEs moved from "open" to "fixed by backport". The updated inventory is not published, because it would describe a running machine; only these counts are.
