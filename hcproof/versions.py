"""Pure-Python version comparison for dpkg (Debian, Ubuntu) and rpm (AlmaLinux, Rocky Linux).

Both functions return -1, 0 or 1, like C's strcmp.

dpkg rules follow dpkg's ``verrevcmp`` (lib/dpkg/version.c):
  * a version is ``[epoch:]upstream[-revision]``; the revision is everything after the
    last hyphen, the epoch everything before the first colon;
  * epochs compare as integers, then upstream and revision with the same algorithm:
    alternating non-digit and digit runs; in non-digit runs letters sort before
    non-letters, ``~`` sorts before everything (even the end of the string);
    digit runs compare numerically.

rpm rules follow rpm's ``rpmvercmp`` (rpmio/rpmvercmp.c) applied to
epoch, then version, then release (as ``rpmdev-vercmp`` / ``rpm.labelCompare`` do):
  * strings are split into alphabetic and numeric segments; other characters are
    separators only;
  * ``~`` sorts before everything, ``^`` sorts after the end of the string but before
    any other segment;
  * numeric segments beat alphabetic ones, numbers compare numerically, letters by
    byte order; if all segments match, the string with segments left over is newer.
"""

from __future__ import annotations

import re

__all__ = [
    "dpkg_compare",
    "dpkg_split",
    "dpkg_upstream",
    "rpm_compare",
    "rpm_split",
    "rpm_upstream",
    "rpmvercmp",
    "compare",
    "upstream_part",
]


# --------------------------------------------------------------------------- dpkg


def dpkg_split(version: str) -> tuple[int, str, str]:
    """Split a dpkg version into (epoch, upstream, revision)."""
    version = version.strip()
    epoch = 0
    if ":" in version:
        head, rest = version.split(":", 1)
        if head.isascii() and head.isdigit():
            epoch = int(head)
            version = rest
    if "-" in version:
        upstream, revision = version.rsplit("-", 1)
    else:
        upstream, revision = version, ""
    return epoch, upstream, revision


def _isdigit(ch: str) -> bool:
    return "0" <= ch <= "9"


def _isalpha(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z")


def _dpkg_order(ch: str) -> int:
    if _isdigit(ch):
        return 0
    if _isalpha(ch):
        return ord(ch)
    if ch == "~":
        return -1
    return ord(ch) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not _isdigit(a[i])) or (j < lb and not _isdigit(b[j])):
            ac = _dpkg_order(a[i]) if i < la else 0
            bc = _dpkg_order(b[j]) if j < lb else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and _isdigit(a[i]) and j < lb and _isdigit(b[j]):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and _isdigit(a[i]):
            return 1
        if j < lb and _isdigit(b[j]):
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def dpkg_compare(a: str, b: str) -> int:
    """Compare two dpkg versions."""
    ea, ua, ra = dpkg_split(a)
    eb, ub, rb = dpkg_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    rc = _verrevcmp(ua, ub)
    if rc:
        return rc
    return _verrevcmp(ra, rb)


def dpkg_upstream(version: str) -> str:
    """The ``epoch:upstream`` part of a dpkg version (revision removed)."""
    epoch, upstream, _ = dpkg_split(version)
    return f"{epoch}:{upstream}"


# --------------------------------------------------------------------------- rpm


def _isalnum(ch: str) -> bool:
    return _isdigit(ch) or _isalpha(ch)


def rpmvercmp(a: str, b: str) -> int:
    """rpm's segment comparison for one field (version or release)."""
    if a == b:
        return 0
    one, two = a, b
    i = j = 0
    while i < len(one) or j < len(two):
        while i < len(one) and not _isalnum(one[i]) and one[i] not in "~^":
            i += 1
        while j < len(two) and not _isalnum(two[j]) and two[j] not in "~^":
            j += 1

        c1 = one[i] if i < len(one) else ""
        c2 = two[j] if j < len(two) else ""

        if c1 == "~" or c2 == "~":
            if c1 != "~":
                return 1
            if c2 != "~":
                return -1
            i += 1
            j += 1
            continue

        if c1 == "^" or c2 == "^":
            if not c1:
                return -1
            if not c2:
                return 1
            if c1 != "^":
                return 1
            if c2 != "^":
                return -1
            i += 1
            j += 1
            continue

        if not (c1 and c2):
            break

        s1, s2 = i, j
        if _isdigit(c1):
            while i < len(one) and _isdigit(one[i]):
                i += 1
            while j < len(two) and _isdigit(two[j]):
                j += 1
            isnum = True
        else:
            while i < len(one) and _isalpha(one[i]):
                i += 1
            while j < len(two) and _isalpha(two[j]):
                j += 1
            isnum = False

        seg1, seg2 = one[s1:i], two[s2:j]
        if not seg1:  # cannot happen (see rpm source); kept for parity
            return -1
        if not seg2:
            return 1 if isnum else -1

        if isnum:
            seg1 = seg1.lstrip("0")
            seg2 = seg2.lstrip("0")
            if len(seg1) != len(seg2):
                return 1 if len(seg1) > len(seg2) else -1
        if seg1 != seg2:
            return 1 if seg1 > seg2 else -1

    rest1 = i < len(one)
    rest2 = j < len(two)
    if not rest1 and not rest2:
        return 0
    return -1 if not rest1 else 1


_EPOCH_RE = re.compile(r"^(\d+):(.*)$")


def rpm_split(evr: str) -> tuple[int, str, str]:
    """Split ``[epoch:]version[-release]`` into (epoch, version, release).

    A missing epoch is 0. A missing release is returned as an empty string.
    """
    evr = evr.strip()
    epoch = 0
    m = _EPOCH_RE.match(evr)
    if m:
        epoch = int(m.group(1))
        evr = m.group(2)
    if "-" in evr:
        version, release = evr.rsplit("-", 1)
    else:
        version, release = evr, ""
    return epoch, version, release


def rpm_compare(a: str, b: str) -> int:
    """Compare two rpm ``[epoch:]version-release`` strings (labelCompare semantics)."""
    ea, va, ra = rpm_split(a)
    eb, vb, rb = rpm_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    rc = rpmvercmp(va, vb)
    if rc:
        return rc
    return rpmvercmp(ra, rb)


def rpm_upstream(evr: str) -> str:
    """The ``epoch:version`` part of an rpm EVR (release removed)."""
    epoch, version, _ = rpm_split(evr)
    return f"{epoch}:{version}"


# --------------------------------------------------------------------------- dispatch


def compare(scheme: str, a: str, b: str) -> int:
    if scheme == "dpkg":
        return dpkg_compare(a, b)
    if scheme == "rpm":
        return rpm_compare(a, b)
    raise ValueError(f"unknown version scheme: {scheme}")


def upstream_part(scheme: str, version: str) -> str:
    if scheme == "dpkg":
        return dpkg_upstream(version)
    if scheme == "rpm":
        return rpm_upstream(version)
    raise ValueError(f"unknown version scheme: {scheme}")
