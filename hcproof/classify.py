"""Classify each (package, vulnerability) pair on a server.

Classes (see SPEC.md):

  open        the installed version is inside an affected range and a fixed version exists
  backport    installed >= the distro's fixed version, the fix was a distro revision of an
              upstream version the distro had already shipped (evidence: an older build of
              the same epoch:upstream version is known to the data), and the server runs that
              same upstream version; a scanner that compares upstream versions may still flag it
  fixed       installed >= fixed version, not a backport (summary count only)
  nofix       affected, and the distro has no fixed version
  notrunning  kernel only: the running kernel is affected, a newer installed kernel is not

Matching is on the source package for Debian/Ubuntu (OSV uses source names there) and on
the binary package name for AlmaLinux/Rocky Linux (OSV uses binary names there).
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from .index import Index, Row, companions
from .inventory import SUPPORTED_RELEASES, Inventory, Package
from .severity import display
from .versions import compare, rpm_split, upstream_part

CLASSES = ("open", "notrunning", "nofix", "backport", "fixed")

LABELS = {
    "open": "Patch available, not installed",
    "notrunning": "Patched on disk, not running: reboot needed",
    "nofix": "No distro fix yet: track or mitigate",
    "backport": "Fixed: a scanner that reads version strings may still flag this",
    "fixed": "Fixed",
}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")

# --------------------------------------------------------------------------- third-party builds

# Version markers that the distro itself never uses. A package carrying one was built by
# someone else (a vendor repository, a PPA, a hosting tool's repository), so the distro's
# fix data does not describe it and we make no claim either way.
_DPKG_THIRD_PARTY = [
    (re.compile(r"deb\.sury\.org|\+0~20\d{6}"), "deb.sury.org (PHP repository) build"),
    (re.compile(r"\+maria~"), "MariaDB repository build"),
    (re.compile(r"nodesource"), "NodeSource repository build"),
    (re.compile(r"pgdg", re.I), "PostgreSQL (PGDG) repository build"),
    (re.compile(r"~bpo\d"), "Debian backports build (not covered by the security tracker data)"),
    (re.compile(r"~(?:focal|jammy|noble|bullseye|bookworm|trixie|plucky|questing|resolute)\b"), "vendor repository build"),
    (re.compile(r"~(?:ubuntu|debian)[.-]\d"), "vendor repository build"),
    (re.compile(r"\.gbp[0-9a-f]{6}"), "third-party snapshot build"),
    (re.compile(r"~ppa\d|\+ppa\d"), "PPA build"),
]
_RPM_THIRD_PARTY = [
    (re.compile(r"\.remi\b"), "Remi repository build"),
    (re.compile(r"\.ngx\b"), "nginx.org build"),
    (re.compile(r"PGDG", re.I), "PostgreSQL (PGDG) repository build"),
    (re.compile(r"nodesource"), "NodeSource repository build"),
]
_RPM_DISTRO_VENDORS = {"AlmaLinux", "Rocky Enterprise Software Foundation", "Red Hat, Inc."}


def third_party_reason(scheme: str, pkg: Package) -> str:
    if scheme == "dpkg":
        for rx, why in _DPKG_THIRD_PARTY:
            if rx.search(pkg.version) or rx.search(pkg.source_version):
                return why
        return ""
    if pkg.vendor and pkg.vendor not in _RPM_DISTRO_VENDORS:
        return "built by " + ("an unknown vendor" if pkg.vendor == "(none)" else pkg.vendor)
    for rx, why in _RPM_THIRD_PARTY:
        if rx.search(pkg.version):
            return why
    return ""


# --------------------------------------------------------------------------- subjects


@dataclass
class Subject:
    name: str  # display name: the source package
    version: str  # installed version that is evaluated (dpkg: source version)
    binaries: list[str]
    match_names: list[str]
    binary_versions: dict[str, str] = field(default_factory=dict)  # rpm: binary -> EVR
    is_kernel: bool = False
    running_version: str = ""
    newest_version: str = ""
    third_party: str = ""


@dataclass
class KernelInfo:
    release: str
    source: str = ""
    running_version: str = ""
    newest_version: str = ""
    installed_versions: list[str] = field(default_factory=list)
    from_package: bool = False
    note: str = ""


_DPKG_KERNEL_PREFIXES = (
    "linux-image-",
    "linux-modules-",
    "linux-headers-",
    "linux-tools-",
    "linux-cloud-tools-",
    "linux-buildinfo-",
    "linux-signed-",
)
_DEB_ARCH_SUFFIXES = ("", "-amd64", "-arm64", "-i386", "-ppc64el", "-s390x", "-armhf", "-armel", "-mips64el", "-riscv64")


def _unsigned_source(src: str) -> str:
    if not src.startswith("linux-signed"):
        return src
    rest = src[len("linux-signed") :]
    return "linux" if rest in _DEB_ARCH_SUFFIXES else "linux" + rest


def _dpkg_cmp(a: str, b: str) -> int:
    return compare("dpkg", a, b)


def _dpkg_kernel(inv: Inventory, installed: list[Package]) -> tuple[Subject | None, KernelInfo, set[str]]:
    """Find the running kernel among installed packages; return its subject and the
    set of source packages that belong to kernels (excluded from normal matching)."""
    info = KernelInfo(release=inv.kernel_release)
    by_name = {p.name: p for p in installed}
    images: dict[str, Package] = {}
    for p in installed:
        for prefix in ("linux-image-unsigned-", "linux-image-"):
            if p.name.startswith(prefix) and p.name[len(prefix) : len(prefix) + 1].isdigit():
                images.setdefault(p.name[len(prefix) :], p)
                break
    kernel_sources = {p.source for p in installed if p.name.startswith(_DPKG_KERNEL_PREFIXES)}

    def source_of(rel: str) -> str:
        for name in (f"linux-modules-{rel}", f"linux-headers-{rel}"):
            p = by_name.get(name)
            if p and p.source.startswith("linux") and p.source != p.name:
                return p.source
        img = images[rel]
        # A pasted dpkg -l has no source names (source == binary name): assume "linux".
        return "linux" if img.source == img.name else _unsigned_source(img.source)

    rel_sources = {rel: source_of(rel) for rel in images}
    kernel_sources |= set(rel_sources.values())

    if not inv.kernel_release:
        info.note = "The running kernel is unknown (pasted package list), so kernel results describe the newest installed kernel package."
    if inv.kernel_release and inv.kernel_release not in images:
        info.note = (
            f"The running kernel {inv.kernel_release} does not match any installed distro kernel package "
            "(a custom, provider or container kernel?). Kernel CVEs were not assessed against it."
        )
        return None, info, kernel_sources
    if not images:
        return None, info, kernel_sources

    if inv.kernel_release:
        src = rel_sources[inv.kernel_release]
        running = images[inv.kernel_release].version
        exact = _exact_running_version(inv)
        if exact:
            running = exact
        info.from_package = True
    else:
        # degraded: the newest kernel of the most common source
        src = max(rel_sources.values(), key=list(rel_sources.values()).count)
        running = ""
    versions = sorted({images[r].version for r, s in rel_sources.items() if s == src}, key=_cmp_key("dpkg"))
    newest = versions[-1]
    info.source, info.running_version, info.newest_version, info.installed_versions = src, running, newest, versions
    subj = Subject(
        name=src,
        version=running or newest,
        binaries=sorted(f"linux-image-{r}" for r, s in rel_sources.items() if s == src),
        match_names=[src],
        is_kernel=True,
        running_version=running,
        newest_version=newest,
    )
    return subj, info, kernel_sources


def _exact_running_version(inv: Inventory) -> str:
    """The package version of the running kernel build, from /proc/version_signature (Ubuntu)
    or ``uname -v`` (Debian). Needed when a kernel package was upgraded in place."""
    sig = inv.kernel_signature.split()
    if len(sig) >= 2 and sig[0] == "Ubuntu" and inv.kernel_release.count("-") >= 2:
        flavour = inv.kernel_release.split("-", 2)[2]
        if sig[1].endswith("-" + flavour):
            return sig[1][: -len(flavour) - 1]
    m = re.search(r"\bDebian (\d\S*)", inv.kernel_build)
    if m and inv.distro == "debian":
        return m.group(1)
    return ""


def _cmp_key(scheme: str):
    from functools import cmp_to_key

    return cmp_to_key(lambda a, b: compare(scheme, a, b))


def _rpm_kernel(inv: Inventory, installed: list[Package]) -> tuple[Subject | None, KernelInfo, set[str]]:
    info = KernelInfo(release=inv.kernel_release, source="kernel")
    cores = [p for p in installed if p.name in ("kernel-core", "kernel") and p.source == "kernel"]
    excluded = {"kernel"}
    if not cores:
        info.note = "No distro kernel package found; kernel CVEs were not assessed."
        return None, info, excluded
    versions = sorted({p.version for p in cores}, key=_cmp_key("rpm"))
    running = ""
    if inv.kernel_release:
        rel = inv.kernel_release
        arch = next((p.arch for p in cores), "")
        if arch and rel.endswith("." + arch):
            rel = rel[: -len(arch) - 1]
        cand = [v for v in versions if v.split(":", 1)[-1] == rel]
        if cand:
            running = cand[0]
            info.from_package = True
        else:
            info.note = (
                f"The running kernel {inv.kernel_release} does not match any installed kernel package. "
                "Kernel CVEs were not assessed against it."
            )
            return None, info, excluded
    else:
        info.note = "The running kernel is unknown (pasted package list), so kernel results describe the newest installed kernel package."
    newest = versions[-1]
    info.running_version, info.newest_version, info.installed_versions = running, newest, versions
    subj = Subject(
        name="kernel",
        version=running or newest,
        binaries=sorted({p.name for p in cores}),
        match_names=["kernel", "kernel-core"],
        binary_versions={},
        is_kernel=True,
        running_version=running,
        newest_version=newest,
    )
    return subj, info, excluded


def build_subjects(inv: Inventory, index: Index | None = None) -> tuple[list[Subject], list[Subject], KernelInfo]:
    """Return (subjects to assess, third-party subjects, kernel info)."""
    installed = inv.installed_packages
    if inv.degraded and inv.scheme == "dpkg" and index is not None:
        # dpkg -l has no source names; use the binary -> source map where the data has one (Ubuntu).
        ecos = [inv.ecosystem, *companions(inv.ecosystem)]
        mapping = index.sources_for_binaries(ecos, [p.name for p in installed])
        for p in installed:
            srcs = mapping.get(p.name)
            if srcs and len(srcs) == 1:
                p.source = next(iter(srcs))

    if inv.scheme == "dpkg":
        kernel, kinfo, kernel_sources = _dpkg_kernel(inv, installed)
    else:
        kernel, kinfo, kernel_sources = _rpm_kernel(inv, installed)

    groups: dict[tuple[str, str], list[Package]] = defaultdict(list)
    for p in installed:
        if p.source in kernel_sources or (inv.scheme == "dpkg" and p.name.startswith(_DPKG_KERNEL_PREFIXES)):
            continue
        groups[(p.source, p.source_version)].append(p)

    subjects: list[Subject] = []
    third: list[Subject] = []
    for (src, srcver), pkgs in sorted(groups.items()):
        reason = next((r for r in (third_party_reason(inv.scheme, p) for p in pkgs) if r), "")
        if inv.scheme == "dpkg":
            subj = Subject(src, srcver, sorted(p.name for p in pkgs), [src])
        else:
            bv = {p.name: p.version for p in pkgs}
            subj = Subject(src, pkgs[0].version, sorted(bv), sorted(bv), binary_versions=bv)
        subj.third_party = reason
        (third if reason else subjects).append(subj)
    if kernel:
        subjects.append(kernel)
    return subjects, third, kinfo


# --------------------------------------------------------------------------- evaluation


@dataclass
class Finding:
    cls: str
    key: str  # CVE ID (or the record ID when there is no CVE)
    package: str
    binaries: list[str]
    installed: str
    fixed: str
    ids: list[str]
    url: str
    severity: str
    rank: int
    summary: str
    published: str
    notes: list[str] = field(default_factory=list)
    backport_of: str = ""
    running: str = ""
    is_kernel: bool = False
    cvss: float = 0.0  # CVSS v3 base score from the data, 0 if none (sorting only)
    via_pro: bool = False


@dataclass
class Result:
    inventory: Inventory
    findings: list[Finding]
    subjects: list[Subject]
    third_party: list[Subject]
    third_party_with_data: set[str]
    kernel: KernelInfo
    warnings: list[str]
    packages_with_data: int
    index_meta: dict

    def by_class(self, cls: str) -> list[Finding]:
        return [f for f in self.findings if f.cls == cls]

    def count(self, cls: str) -> tuple[int, int]:
        """(distinct vulnerability IDs, distinct packages) for a class."""
        fs = self.by_class(cls)
        return len({f.key for f in fs}), len({f.package for f in fs})


def _strip_epoch(v: str) -> str:
    return v.split(":", 1)[1] if ":" in v and v.split(":", 1)[0].isdigit() else v


class _Evaluator:
    def __init__(self, scheme: str, epoch_known: bool):
        self.scheme = scheme
        self.epoch_known = epoch_known

    def cmp(self, a: str, b: str) -> int:
        if not self.epoch_known:
            a, b = _strip_epoch(a), _strip_epoch(b)
        return compare(self.scheme, a, b)

    def comparable(self, version: str, other: str) -> bool:
        """rpm module streams: only compare builds of the same major version."""
        if self.scheme != "rpm" or (".module" not in version and ".module" not in other):
            return True
        return rpm_split(version)[1].split(".")[0] == rpm_split(other)[1].split(".")[0]

    def row_status(self, version: str, row: Row) -> str:
        """'affected', 'fixed' or 'unaffected' for one affected range."""
        ref = row.fixed or row.last_affected or (row.introduced if row.introduced not in ("", "0") else "")
        if ref and not self.comparable(version, ref):
            return "unaffected"
        if row.introduced not in ("", "0") and self.cmp(version, row.introduced) < 0:
            return "unaffected"
        if row.fixed:
            return "affected" if self.cmp(version, row.fixed) < 0 else "fixed"
        if row.last_affected:
            return "affected" if self.cmp(version, row.last_affected) <= 0 else "unaffected"
        return "affected"


def _keys(row: Row) -> list[str]:
    if row.kind == "advisory":
        cves = [a for a in row.aliases if _CVE_RE.match(a)]
        return cves or [row.vuln_id]
    if _CVE_RE.match(row.vuln_id):
        return [row.vuln_id]
    if row.aliases and _CVE_RE.match(row.aliases[0]):
        return [row.aliases[0]]
    return [row.vuln_id]


@dataclass
class _Decision:
    status: str  # open | nofix | fixed | unaffected
    row: Row | None = None
    via_pro: bool = False


def _record_status(ev: _Evaluator, version: str, rows: list[Row]) -> tuple[str, Row]:
    """Combine the ranges of one record for one package: affected wins within a record."""
    best_fixed = None
    for row in rows:
        st = ev.row_status(version, row)
        if st == "affected":
            return ("open" if row.fixed else "nofix"), row
        if st == "fixed" and (best_fixed is None or ev.cmp(row.fixed, best_fixed.fixed) > 0):
            best_fixed = row
    if best_fixed is not None:
        return "fixed", best_fixed
    return "unaffected", rows[0]


def _combine(ev: _Evaluator, statuses: list[tuple[str, Row]]) -> _Decision:
    """Combine several records about the same issue: a record saying 'fixed' wins
    (no false 'vulnerable' claim); otherwise the lowest fixed version that applies."""
    fixed = [r for s, r in statuses if s == "fixed"]
    if fixed:
        return _Decision("fixed", max(fixed, key=_cmp_key_rows(ev)))
    opened = [r for s, r in statuses if s == "open"]
    if opened:
        return _Decision("open", min(opened, key=_cmp_key_rows(ev)))
    nofix = [r for s, r in statuses if s == "nofix"]
    if nofix:
        return _Decision("nofix", nofix[0])
    return _Decision("unaffected")


def _cmp_key_rows(ev: _Evaluator):
    from functools import cmp_to_key

    return cmp_to_key(lambda a, b: ev.cmp(a.fixed or "0", b.fixed or "0"))


def _decide(ev: _Evaluator, version: str, rows: list[Row], primary_eco: str) -> _Decision:
    """Decide one issue for one installed version, from every row that mentions it."""
    issue_rows = [r for r in rows if r.kind == "issue"]
    use = issue_rows or rows

    def per_record(rs: list[Row]) -> list[tuple[str, Row]]:
        recs: dict[str, list[Row]] = defaultdict(list)
        for r in rs:
            recs[r.vuln_id].append(r)
        return [_record_status(ev, version, v) for v in recs.values()]

    main = _combine(ev, per_record([r for r in use if r.ecosystem == primary_eco]))
    pro_rows = [r for r in use if r.ecosystem != primary_eco]
    if not pro_rows or main.status in ("fixed", "open"):
        return main
    pro = _combine(ev, per_record(pro_rows))
    if pro.status in ("fixed", "open"):
        pro.via_pro = True
        return pro
    if main.status == "nofix" or pro.status == "nofix":
        return main if main.status == "nofix" else pro
    return main


def _finding(cls, key, subj, installed, dec: _Decision, rows: list[Row], ev: _Evaluator) -> Finding:
    row = dec.row
    advisories = sorted({r.vuln_id for r in rows if r.kind == "advisory"})
    related = []
    for r in rows:
        for a in r.aliases:
            if not _CVE_RE.match(a) and a not in related and a not in advisories:
                related.append(a)
    other_cves = sorted({a for r in rows if r.kind == "issue" for a in r.aliases if _CVE_RE.match(a) and a != key})
    ids = [key] + other_cves + advisories + related[:3]
    issue = next((r for r in rows if r.kind == "issue"), None)
    url = (issue or row).url
    vendor = row.rating or row.vendor_severity
    if vendor and row.kind == "advisory" and not row.rating:
        vendor = vendor.replace(":", " advisory:", 1)
    notes = []
    if row.note:
        notes.append(row.note)
    if dec.via_pro:
        notes.append("Fix available with Ubuntu Pro (ESM)" if cls == "open" else "Fixed by an Ubuntu Pro (ESM) update")
    if subj.third_party:
        notes.append(subj.third_party)
    return Finding(
        cls=cls,
        key=key,
        package=subj.name,
        binaries=subj.binaries,
        installed=installed,
        fixed=row.fixed,
        ids=ids,
        url=url,
        severity=display(vendor, row.cvss),
        rank=row.rating_rank or row.vendor_rank or row.cvss_rank,
        summary=row.summary,
        published=row.published,
        notes=notes,
        cvss=float(row.cvss) if row.cvss else 0.0,
        via_pro=dec.via_pro,
    )


def _evaluate_subject(ev: _Evaluator, subj: Subject, rows: list[Row], primary_eco: str) -> list[Finding]:
    by_key: dict[str, list[Row]] = defaultdict(list)
    for r in rows:
        for k in _keys(r):
            by_key[k].append(r)
    out: list[Finding] = []
    for key, krows in by_key.items():
        if subj.is_kernel:
            out.extend(_evaluate_kernel_key(ev, subj, key, krows, primary_eco))
            continue
        if ev.scheme == "rpm":
            # Each row names one binary; evaluate it against that binary's own version.
            decisions = []
            for binary, version in subj.binary_versions.items():
                brows = [r for r in krows if r.package == binary]
                if brows:
                    decisions.append((version, _decide(ev, version, brows, primary_eco)))
            if not decisions:
                continue
            order = {"open": 0, "nofix": 1, "fixed": 2, "unaffected": 3}
            version, dec = min(decisions, key=lambda d: order[d[1].status])
        else:
            version = subj.version
            dec = _decide(ev, version, krows, primary_eco)
        if dec.status == "unaffected":
            continue
        if dec.status == "fixed":
            cls = "fixed"
            if dec.row.backport_of and upstream_part(ev.scheme, version) == upstream_part(ev.scheme, dec.row.fixed):
                cls = "backport"
        else:
            cls = dec.status
        f = _finding(cls, key, subj, version, dec, krows, ev)
        if cls == "backport":
            f.backport_of = dec.row.backport_of
        out.append(f)
    return out


def _evaluate_kernel_key(ev: _Evaluator, subj: Subject, key: str, rows: list[Row], primary_eco: str) -> list[Finding]:
    running = subj.running_version
    newest = subj.newest_version
    if not running:
        dec = _decide(ev, newest, rows, primary_eco)
        return _kernel_finding(ev, subj, key, rows, dec, newest, "")
    dec_run = _decide(ev, running, rows, primary_eco)
    if dec_run.status == "open" and ev.cmp(newest, running) > 0:
        dec_new = _decide(ev, newest, rows, primary_eco)
        if dec_new.status == "fixed":
            f = _finding("notrunning", key, subj, newest, dec_new, rows, ev)
            f.running = running
            f.is_kernel = True
            return [f]
    return _kernel_finding(ev, subj, key, rows, dec_run, running, running)


def _kernel_finding(ev, subj, key, rows, dec: _Decision, version: str, running: str) -> list[Finding]:
    if dec.status == "unaffected":
        return []
    cls = dec.status
    if cls == "fixed" and dec.row.backport_of and upstream_part(ev.scheme, version) == upstream_part(ev.scheme, dec.row.fixed):
        cls = "backport"
    f = _finding(cls, key, subj, version, dec, rows, ev)
    f.running = running
    f.is_kernel = True
    if cls == "backport":
        f.backport_of = dec.row.backport_of
    if cls == "open" and subj.newest_version and running and subj.newest_version != running:
        f.notes.append(f"Newest installed kernel {subj.newest_version} is not fixed either")
    return [f]


# --------------------------------------------------------------------------- data notes


def data_notes(inv: Inventory, index_meta: dict) -> list[str]:
    eco = inv.ecosystem
    notes = []
    if eco not in SUPPORTED_RELEASES:
        notes.append(f"{inv.pretty_name} is outside the v1 tested scope (Debian 11/12, Ubuntu 20.04/22.04/24.04 LTS, AlmaLinux 8/9, Rocky Linux 8/9).")
    if eco == "Debian:11":
        notes.append(
            "Debian 11 (bullseye) left Debian LTS in August 2026. OSV now holds per-CVE data for only a small "
            "part of bullseye, plus DSA/DLA advisories up to March 2026. Results for this release are incomplete; "
            "issues without a fix are mostly missing."
        )
    if eco == "Ubuntu:20.04:LTS":
        notes.append(
            "Ubuntu 20.04 left standard support in May 2025. Most newer fixes ship only through Ubuntu Pro (ESM); "
            "those are marked 'Ubuntu Pro'."
        )
    if inv.distro in ("almalinux", "rocky"):
        notes.append(
            f"The {eco.split(':')[0]} OSV data lists released fixes (security advisories) only. Vulnerabilities "
            "without a fix are not in the data, so 'No distro fix yet' cannot be filled for this distribution."
        )
    if inv.distro == "rocky":
        notes.append(
            "Rocky Linux OSV data covered fewer packages and CVEs than AlmaLinux data for the same RHEL release "
            "when this tool was built (Rocky 9: about 4,600 CVEs, AlmaLinux 9: about 5,700). Some fixed issues may be missing."
        )
    if inv.degraded:
        if inv.scheme == "dpkg":
            notes.append(
                "Degraded mode: a pasted dpkg -l has no source package names. Packages were matched by binary name"
                + (" and Ubuntu's binary-to-source map" if inv.distro == "ubuntu" else "")
                + "; some issues will be missed. Use the collector for a full result."
            )
        else:
            notes.append("Degraded mode: a pasted rpm -qa. Use the collector for a full result (vendor and source data).")
        if inv.scheme == "rpm" and not inv.epoch_known:
            notes.append("Epochs were not in the pasted list, so versions were compared without epochs.")
    return notes


# --------------------------------------------------------------------------- entry point


def classify(inv: Inventory, index: Index) -> Result:
    subjects, third, kinfo = build_subjects(inv, index)
    ecos = [inv.ecosystem, *companions(inv.ecosystem)]
    missing = [e for e in ecos if e not in index.ecosystems]
    if inv.ecosystem in missing:
        raise ValueError(f"the index has no data for {inv.ecosystem}")
    ecos = [e for e in ecos if e not in missing]

    names = sorted({n for s in subjects + third for n in s.match_names})
    rows_by_pkg: dict[str, list[Row]] = defaultdict(list)
    for r in index.rows_for(ecos, names):
        rows_by_pkg[r.package].append(r)

    ev = _Evaluator(inv.scheme, inv.epoch_known)
    findings: list[Finding] = []
    with_data = 0
    for subj in subjects:
        rows = [r for n in subj.match_names for r in rows_by_pkg.get(n, [])]
        if not rows:
            continue
        with_data += 1
        findings.extend(_evaluate_subject(ev, subj, rows, inv.ecosystem))

    third_with_data = {s.name for s in third if any(rows_by_pkg.get(n) for n in s.match_names)}
    warnings = data_notes(inv, index.meta)
    if kinfo.note:
        warnings.append(kinfo.note)
    findings.sort(key=lambda f: (CLASSES.index(f.cls), -f.rank, -f.cvss, f.package, _key_sort(f.key)))
    return Result(inv, findings, subjects, third, third_with_data, kinfo, warnings, with_data, index.meta)


def _key_sort(key: str):
    m = re.match(r"CVE-(\d{4})-(\d+)$", key)
    return (0, int(m.group(1)), int(m.group(2)), "") if m else (1, 0, 0, key)
