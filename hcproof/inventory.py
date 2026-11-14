"""Parse an inventory: the collector's output, or a pasted ``dpkg -l`` / ``rpm -qa`` (degraded mode)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

__all__ = [
    "Package",
    "Inventory",
    "InventoryError",
    "parse_inventory",
    "ecosystem_for",
    "sanitise",
    "SUPPORTED_RELEASES",
]

# Releases in the v1 scope. Other releases of the same distros are accepted, but
# the report says they are outside the tested scope.
SUPPORTED_RELEASES = {
    "Debian:11",
    "Debian:12",
    "Ubuntu:20.04:LTS",
    "Ubuntu:22.04:LTS",
    "Ubuntu:24.04:LTS",
    "AlmaLinux:8",
    "AlmaLinux:9",
    "Rocky Linux:8",
    "Rocky Linux:9",
}

_RPM_ARCHES = {"x86_64", "aarch64", "noarch", "i686", "i386", "ppc64le", "s390x", "armv7hl", "src"}


class InventoryError(ValueError):
    pass


@dataclass
class Package:
    name: str
    version: str  # dpkg: binary version; rpm: epoch:version-release
    arch: str
    source: str
    source_version: str
    installed: bool = True
    vendor: str = ""  # rpm only; "" when unknown


@dataclass
class Inventory:
    scheme: str  # "dpkg" or "rpm"
    distro: str  # "debian", "ubuntu", "almalinux", "rocky"
    release: str  # "12", "24.04", "9"
    ecosystem: str  # OSV ecosystem, e.g. "Ubuntu:24.04:LTS"
    pretty_name: str
    packages: list[Package]
    sha256: str
    degraded: bool = False
    kernel_release: str = ""
    kernel_build: str = ""
    kernel_signature: str = ""
    kernel_images: list[str] = field(default_factory=list)
    reboot_required: bool | None = None
    reboot_packages: list[str] = field(default_factory=list)
    epoch_known: bool = True  # False for a pasted `rpm -qa` without epochs
    os_release: dict[str, str] = field(default_factory=dict)

    @property
    def installed_packages(self) -> list[Package]:
        return [p for p in self.packages if p.installed]


def ecosystem_for(distro_id: str, version_id: str) -> tuple[str, str, str]:
    """Map os-release ID / VERSION_ID to (distro, release, OSV ecosystem)."""
    distro = distro_id.strip().lower()
    version_id = version_id.strip()
    if distro == "debian":
        major = version_id.split(".")[0]
        if not major.isdigit():
            raise InventoryError(f"Debian release not recognised: {version_id!r} (testing/sid are not supported)")
        return "debian", major, f"Debian:{major}"
    if distro == "ubuntu":
        if not re.fullmatch(r"\d{2}\.\d{2}", version_id):
            raise InventoryError(f"Ubuntu release not recognised: {version_id!r}")
        year, month = version_id.split(".")
        lts = month == "04" and int(year) % 2 == 0
        return "ubuntu", version_id, f"Ubuntu:{version_id}" + (":LTS" if lts else "")
    if distro in ("almalinux", "rocky"):
        major = version_id.split(".")[0]
        if not major.isdigit():
            raise InventoryError(f"{distro} release not recognised: {version_id!r}")
        name = "AlmaLinux" if distro == "almalinux" else "Rocky Linux"
        return distro, major, f"{name}:{major}"
    raise InventoryError(
        f"Distribution {distro_id!r} is not supported in v1 "
        "(supported: Debian, Ubuntu, AlmaLinux, Rocky Linux)"
    )


def _parse_os_release(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def _parse_dpkg_source(binary: str, version: str, source_field: str) -> tuple[str, str]:
    source_field = source_field.strip()
    if not source_field:
        return binary, version
    m = re.fullmatch(r"(\S+)\s*\((\S+)\)", source_field)
    if m:
        return m.group(1), m.group(2)
    return source_field.split()[0], version


def _parse_srpm(srpm: str) -> tuple[str, str]:
    """``openssh-8.7p1-38.el9_4.1.src.rpm`` -> (``openssh``, ``8.7p1-38.el9_4.1``)."""
    if srpm.endswith(".src.rpm"):
        srpm = srpm[: -len(".src.rpm")]
    elif srpm.endswith(".nosrc.rpm"):
        srpm = srpm[: -len(".nosrc.rpm")]
    parts = srpm.rsplit("-", 2)
    if len(parts) != 3:
        return srpm, ""
    return parts[0], f"{parts[1]}-{parts[2]}"


def _split_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if line.startswith("## "):
            current = line[3:].strip()
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(line)
    return sections


def _kv(lines: list[str]) -> list[tuple[str, str]]:
    out = []
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            out.append((k.strip(), v.strip()))
    return out


def _parse_collector(text: str, sha: str) -> Inventory:
    sections = _split_sections(text)
    if "packages" not in sections:
        raise InventoryError("collector output has no '## packages' section (was it cut off?)")
    osr = _parse_os_release(sections.get("os-release", []))
    if "ID" not in osr or "VERSION_ID" not in osr:
        raise InventoryError("collector output has no usable /etc/os-release (ID and VERSION_ID are needed)")
    distro, release, eco = ecosystem_for(osr["ID"], osr["VERSION_ID"])

    inv = Inventory(
        scheme="dpkg" if distro in ("debian", "ubuntu") else "rpm",
        distro=distro,
        release=release,
        ecosystem=eco,
        pretty_name=osr.get("PRETTY_NAME", f"{distro} {release}"),
        packages=[],
        sha256=sha,
        os_release=osr,
    )

    for k, v in _kv(sections.get("kernel", [])):
        if k == "release":
            inv.kernel_release = v
        elif k == "build":
            inv.kernel_build = v
        elif k == "signature":
            inv.kernel_signature = v
        elif k == "image":
            inv.kernel_images.append(v)

    if "reboot-required" in sections:
        for k, v in _kv(sections["reboot-required"]):
            if k == "flag":
                inv.reboot_required = v == "yes"
            elif k == "pkg" and v not in inv.reboot_packages:
                inv.reboot_packages.append(v)

    fmt = None
    for line in sections["packages"]:
        if line.startswith("format="):
            fmt = line.split("=", 1)[1].strip()
            continue
        if not line.strip():
            continue
        cols = line.split("\t")
        if fmt == "dpkg":
            if len(cols) < 5:
                continue
            status, name, version, arch, source_field = cols[:5]
            if not version:
                continue
            src, srcver = _parse_dpkg_source(name, version, source_field)
            # ${Status} is "want ok state"; the files are on disk in these states.
            installed = status.split()[-1:] in (["installed"], ["triggers-pending"], ["triggers-awaited"],
                                                 ["half-configured"], ["unpacked"])
            inv.packages.append(Package(name, version, arch, src, srcver, installed))
        elif fmt == "rpm":
            if len(cols) < 6:
                continue
            name, epoch, version, release, arch, srpm = cols[:6]
            vendor = cols[6].strip() if len(cols) > 6 else ""
            if name == "gpg-pubkey":
                continue
            epoch = "0" if epoch in ("", "(none)") else epoch
            evr = f"{epoch}:{version}-{release}"
            src, srcver = _parse_srpm(srpm) if srpm and srpm != "(none)" else (name, f"{version}-{release}")
            inv.packages.append(
                Package(name, evr, arch, src, f"{epoch}:{srcver}" if srcver else evr, vendor=vendor)
            )
    if fmt not in ("dpkg", "rpm"):
        raise InventoryError("collector found no dpkg or rpm package database")
    if fmt != inv.scheme:
        raise InventoryError(f"package format {fmt} does not match the distribution {distro}")
    return inv


_DPKG_L_RE = re.compile(r"^([uirhp][nicurhUFWt])[ R]?\s+(\S+)\s+(\S+)\s+(\S+)")


def _parse_dpkg_l(text: str) -> list[Package]:
    pkgs = []
    for line in text.splitlines():
        m = _DPKG_L_RE.match(line)
        if not m:
            continue
        state, name, version, arch = m.groups()
        name = name.split(":", 1)[0]
        installed = state[1] == "i"
        # Degraded mode: dpkg -l has no source package. We use the binary name.
        pkgs.append(Package(name, version, arch, name, version, installed))
    return pkgs


_NEVRA_RE = re.compile(r"^(?P<name>.+)-(?:(?P<epoch>\d+):)?(?P<version>[^-]+)-(?P<release>[^-]+)$")


def _parse_rpm_qa(text: str) -> list[Package]:
    pkgs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        arch = ""
        if "." in token:
            head, tail = token.rsplit(".", 1)
            if tail in _RPM_ARCHES:
                token, arch = head, tail
        m = _NEVRA_RE.match(token)
        if not m or m.group("name") == "gpg-pubkey":
            continue
        epoch = m.group("epoch")
        evr = (f"{epoch}:" if epoch else "") + f"{m.group('version')}-{m.group('release')}"
        pkgs.append(Package(m.group("name"), evr, arch, m.group("name"), evr))
    return pkgs


def parse_inventory(data: bytes, os_hint: str | None = None) -> Inventory:
    """Parse collector output, or (degraded mode) a pasted dpkg -l / rpm -qa plus ``os_hint``.

    ``os_hint`` looks like ``debian:12``, ``ubuntu:24.04``, ``almalinux:9`` or ``rocky:9``.
    """
    sha = hashlib.sha256(data).hexdigest()
    text = data.decode("utf-8", errors="replace")
    if text.lstrip().startswith("# hcproof-collector"):
        return _parse_collector(text, sha)

    if not os_hint:
        raise InventoryError(
            "This is not collector output. For a pasted `dpkg -l` or `rpm -qa`, "
            "pass the OS too, e.g. --os ubuntu:24.04"
        )
    if ":" not in os_hint:
        raise InventoryError("--os must look like debian:12, ubuntu:24.04, almalinux:9 or rocky:9")
    distro_id, version_id = os_hint.split(":", 1)
    distro, release, eco = ecosystem_for(distro_id, version_id)
    scheme = "dpkg" if distro in ("debian", "ubuntu") else "rpm"
    pkgs = _parse_dpkg_l(text) if scheme == "dpkg" else _parse_rpm_qa(text)
    if not pkgs:
        raise InventoryError(f"no packages found in the pasted {'dpkg -l' if scheme == 'dpkg' else 'rpm -qa'} output")
    inv = Inventory(
        scheme=scheme,
        distro=distro,
        release=release,
        ecosystem=eco,
        pretty_name=f"{distro.capitalize()} {version_id}",
        packages=pkgs,
        sha256=sha,
        degraded=True,
    )
    if scheme == "rpm":
        inv.epoch_known = any(":" in p.version for p in pkgs)
    return inv


# --------------------------------------------------------------------------- sanitise

_KEEP_OS_KEYS = {
    "NAME", "PRETTY_NAME", "ID", "ID_LIKE", "VERSION", "VERSION_ID", "VERSION_CODENAME",
    "UBUNTU_CODENAME", "PLATFORM_ID", "CPE_NAME",
}
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b")


def sanitise(text: str) -> str:
    """Return collector output reduced to package and OS data.

    Keeps only the known sections and keys, drops anything else, and blanks any
    IPv4/IPv6 address that might appear in free text (it should not).
    """
    sections = _split_sections(text)
    out = ["# hcproof-collector 1", "## os-release"]
    for line in sections.get("os-release", []):
        if "=" in line and line.split("=", 1)[0].strip() in _KEEP_OS_KEYS:
            out.append(line)
    out.append("## kernel")
    for k, v in _kv(sections.get("kernel", [])):
        if k in ("release", "build", "arch", "signature", "image"):
            out.append(f"{k}={v}")
    out.append("## reboot-required")
    for k, v in _kv(sections.get("reboot-required", [])):
        if k in ("flag", "pkg"):
            out.append(f"{k}={v}")
    out.append("## packages")
    for line in sections.get("packages", []):
        if line.startswith("format=") or line.count("\t") >= 4:  # dpkg rows have 5 columns, rpm rows 6-7
            out.append(line)
    out.append("## end")
    result = "\n".join(out) + "\n"
    # Package versions can look like dotted quads (e.g. 1.2.3.4), so addresses are
    # only blanked outside the package table.
    head, sep, tail = result.partition("## packages")
    head = _IPV6_RE.sub("::", _IPV4_RE.sub("0.0.0.0", head))
    return head + sep + tail
