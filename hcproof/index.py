"""The SQLite index: a compact, query-ready copy of the OSV data we need.

The same file format serves the CLI (one file per ecosystem family, in the cache), the
prebuilt index and other programs (one combined file, built by ``hc-proof index build``).
Schema version 1:

    meta(key, value)                           snapshot_utc, built_utc, per-family snapshot and hash
    ecosystem(eco, name)                       e.g. 3 -> "Ubuntu:24.04:LTS"
    vuln(vid, vuln_id, kind, aliases, ...)     one row per OSV record
    affected(eco, package, vid, introduced, fixed, last_affected, rating, rating_rank, note)
                                               one row per (record, package, affected range);
                                               indexed on (eco, package)
    backport(eco, package, fixed, earlier)     backport evidence for a fixed version
    binaries(eco, binary, source)              Ubuntu binary -> source package map (degraded mode)
    VIEW vulns                                 the flat shape other programs read:
        (ecosystem, package, vuln_id, aliases, introduced, fixed, severity, summary,
         published, url, last_affected, backport_of, note, kind, severity_rank)

Integer keys keep the file small (Ubuntu alone has over two million affected rows).
See INTEGRATION.md for column meanings and example queries.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import cmp_to_key
from pathlib import Path

from . import __version__
from .osv import Snapshot, bulk_url, family_of, iter_records
from .severity import entry_rating, record_severity
from .versions import compare, upstream_part

SCHEMA_VERSION = "1"

# The v1 scope.
SCOPE_ECOSYSTEMS = [
    "Debian:11",
    "Debian:12",
    "Ubuntu:20.04:LTS",
    "Ubuntu:22.04:LTS",
    "Ubuntu:24.04:LTS",
    "AlmaLinux:8",
    "AlmaLinux:9",
    "Rocky Linux:8",
    "Rocky Linux:9",
]
# Newer releases the CLI also accepts (reported as outside the tested scope).
EXTRA_ECOSYSTEMS = ["Debian:13", "Ubuntu:26.04:LTS", "AlmaLinux:10", "Rocky Linux:10"]

# Records we do not index: Ubuntu USNs and Livepatch notices (the per-CVE records carry
# the same fixes and list the USN IDs), AlmaLinux bug-fix and enhancement advisories.
SKIP_PREFIXES = ("USN-", "LSN-", "ALBA-", "ALEA-")
# Records that are advisories (may cover several CVEs). Everything else is a per-issue record.
ADVISORY_PREFIXES = ("DSA-", "DLA-", "DTSA-", "ALSA-", "RLSA-", "RXSA-", "RHSA-")
# Derived per-distro IDs that duplicate a CVE ID; left out of the alias list.
_DERIVED_ID_RE = re.compile(r"^(DEBIAN|UBUNTU)-CVE-")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")

_URL_HINT = {
    "Debian": "security-tracker.debian.org",
    "Ubuntu": "ubuntu.com/security",
    "AlmaLinux": "errata.almalinux.org",
    "Rocky Linux": "errata.rockylinux.org",
}

_SEVERITY_SQL = """
CASE
  WHEN (CASE WHEN a.rating != '' THEN a.rating ELSE v.vendor_severity END) != '' AND v.cvss != ''
    THEN (CASE WHEN a.rating != '' THEN a.rating ELSE v.vendor_severity END) || ' · CVSS ' || v.cvss
  WHEN (CASE WHEN a.rating != '' THEN a.rating ELSE v.vendor_severity END) != ''
    THEN (CASE WHEN a.rating != '' THEN a.rating ELSE v.vendor_severity END)
  WHEN v.cvss != '' THEN 'CVSS ' || v.cvss
  ELSE 'unrated'
END"""

_SCHEMA = f"""
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE ecosystem(eco INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE vuln(
    vid INTEGER PRIMARY KEY,
    vuln_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    aliases TEXT NOT NULL,
    vendor_severity TEXT NOT NULL,
    vendor_rank INTEGER NOT NULL,
    cvss TEXT NOT NULL,
    cvss_rank INTEGER NOT NULL,
    cvss_vector TEXT NOT NULL,
    summary TEXT NOT NULL,
    published TEXT NOT NULL,
    url TEXT NOT NULL
);
CREATE TABLE affected(
    eco INTEGER NOT NULL,
    package TEXT NOT NULL,
    vid INTEGER NOT NULL,
    introduced TEXT NOT NULL,
    fixed TEXT NOT NULL,
    last_affected TEXT NOT NULL,
    rating TEXT NOT NULL,
    rating_rank INTEGER NOT NULL,
    note TEXT NOT NULL
);
CREATE TABLE backport(eco INTEGER NOT NULL, package TEXT NOT NULL, fixed TEXT NOT NULL, earlier TEXT NOT NULL,
                      PRIMARY KEY (eco, package, fixed)) WITHOUT ROWID;
CREATE TABLE binaries(eco INTEGER NOT NULL, binary TEXT NOT NULL, source TEXT NOT NULL,
                      PRIMARY KEY (eco, binary, source)) WITHOUT ROWID;
CREATE VIEW vulns AS
SELECT e.name AS ecosystem, a.package, v.vuln_id, v.aliases, a.introduced, a.fixed,
       {_SEVERITY_SQL} AS severity,
       v.summary, v.published, v.url,
       a.last_affected, COALESCE(b.earlier, '') AS backport_of, a.note, v.kind,
       CASE WHEN a.rating_rank > 0 THEN a.rating_rank
            WHEN v.vendor_rank > 0 THEN v.vendor_rank
            ELSE v.cvss_rank END AS severity_rank
FROM affected a
JOIN ecosystem e ON e.eco = a.eco
JOIN vuln v ON v.vid = a.vid
LEFT JOIN backport b ON b.eco = a.eco AND b.package = a.package AND b.fixed = a.fixed;
"""


def scheme_for(ecosystem: str) -> str:
    return "dpkg" if family_of(ecosystem) in ("Debian", "Ubuntu") else "rpm"


def companions(ecosystem: str) -> list[str]:
    """Extra ecosystems read together with ``ecosystem`` (Ubuntu Pro for Ubuntu LTS)."""
    m = re.fullmatch(r"Ubuntu:(\d{2}\.\d{2}):LTS", ecosystem)
    return [f"Ubuntu:Pro:{m.group(1)}:LTS"] if m else []


def with_companions(ecosystems: list[str]) -> list[str]:
    out: list[str] = []
    for e in ecosystems:
        for x in [e, *companions(e)]:
            if x not in out:
                out.append(x)
    return out


def local_ecosystems(family: str) -> list[str]:
    return with_companions([e for e in SCOPE_ECOSYSTEMS + EXTRA_ECOSYSTEMS if family_of(e) == family])


# --------------------------------------------------------------------------- build helpers


_KERNEL_PREAMBLE = re.compile(r"^In the Linux kernel, the following vulnerability has been resolved:\s*", re.I)


def _summary(rec: dict) -> str:
    text = str(rec.get("summary") or "").strip()
    if not text:
        details = _KERNEL_PREAMBLE.sub("", " ".join(str(rec.get("details") or "").split()))
        m = re.match(r"(.{20,}?[.!?])(\s|$)", details)
        text = m.group(1) if m else details
    text = " ".join(text.split())
    return text if len(text) <= 160 else text[:157].rstrip() + "..."


def _aliases(rec: dict) -> list[str]:
    own = rec["id"]
    seen: list[str] = []
    for key in ("aliases", "upstream", "related"):
        for a in rec.get(key) or []:
            if isinstance(a, str) and a != own and a not in seen and not _DERIVED_ID_RE.match(a):
                seen.append(a)
    cves = sorted((a for a in seen if _CVE_RE.match(a)), key=_cve_sort_key)
    others = [a for a in seen if not _CVE_RE.match(a)]
    if _DERIVED_ID_RE.match(own):
        derived = own.split("-", 1)[1]
        if _CVE_RE.match(derived) and derived not in cves:
            cves.insert(0, derived)
    return cves + others


def _cve_sort_key(cve: str) -> tuple[int, int]:
    _, year, num = cve.split("-")
    return int(year), int(num)


def _url(rec: dict, family: str) -> str:
    """The distro's own page for this record: the CVE page for per-CVE records, else the advisory."""
    vid = rec["id"]
    if family == "Ubuntu" and vid.startswith("UBUNTU-CVE-"):
        return f"https://ubuntu.com/security/{vid.split('-', 1)[1]}"
    if family == "Debian" and vid.startswith("DEBIAN-CVE-"):
        return f"https://security-tracker.debian.org/tracker/{vid.split('-', 1)[1]}"
    hint = _URL_HINT[family]
    refs = [r for r in rec.get("references") or [] if isinstance(r, dict) and isinstance(r.get("url"), str)]
    for want_type in ("ADVISORY", None):
        for r in refs:
            if hint in r["url"] and (want_type is None or r.get("type") == want_type):
                return r["url"]
    vid = rec["id"]
    if family == "Debian":
        tracker_id = vid.split("-", 1)[1] if vid.startswith("DEBIAN-") else vid
        return f"https://security-tracker.debian.org/tracker/{tracker_id}"
    if family == "Ubuntu" and vid.startswith("UBUNTU-CVE-"):
        return f"https://ubuntu.com/security/{vid.split('-', 1)[1]}"
    return f"https://osv.dev/vulnerability/{vid}"


def _segments(events: list[dict]) -> list[tuple[str, str, str]]:
    """OSV range events -> [(introduced, fixed, last_affected)]."""
    out = []
    cur: str | None = None
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if "introduced" in ev:
            if cur is not None:
                out.append((cur, "", ""))
            cur = str(ev["introduced"])
        elif "fixed" in ev:
            out.append((cur if cur is not None else "0", str(ev["fixed"]), ""))
            cur = None
        elif "last_affected" in ev:
            out.append((cur if cur is not None else "0", "", str(ev["last_affected"])))
            cur = None
    if cur is not None:
        out.append((cur, "", ""))
    return out


@dataclass
class BuildStats:
    records: int = 0
    rows: int = 0
    skipped_versions_only: int = 0
    per_ecosystem: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    seconds: float = 0.0
    bytes: int = 0


def build(out_path: Path, ecosystems: list[str], snapshots: dict[str, Snapshot], log=None) -> BuildStats:
    """Build an index for ``ecosystems`` from the given family snapshots into ``out_path``.

    The file is written next to ``out_path`` and moved into place at the end, so a
    reader never sees a half-built index.
    """
    t0 = time.monotonic()
    stats = BuildStats()
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_name(out_path.name + f".tmp{os.getpid()}")
    tmp.unlink(missing_ok=True)
    db = sqlite3.connect(tmp)
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")
    db.executescript(_SCHEMA)

    by_family: dict[str, list[str]] = defaultdict(list)
    for e in ecosystems:
        by_family[family_of(e)].append(e)
    eco_ids = {name: i for i, name in enumerate(sorted(ecosystems), start=1)}
    db.executemany("INSERT INTO ecosystem VALUES (?, ?)", [(i, n) for n, i in eco_ids.items()])

    known: dict[tuple[int, str], set[str]] = defaultdict(set)
    binaries: set[tuple[int, str, str]] = set()
    next_vid = 1

    for family, ecos in by_family.items():
        snap = snapshots[family]
        targets = set(ecos)
        if log:
            log(f"Indexing {family} ({', '.join(ecos)}) from snapshot {snap.snapshot_utc} ...")
        vuln_rows = []
        aff_rows = []
        for rec in iter_records(snap.path, targets):
            rid = rec["id"]
            if rec.get("withdrawn") or rid.startswith(SKIP_PREFIXES):
                continue
            rec_aff = []
            vid = next_vid
            for aff in rec.get("affected") or []:
                if not isinstance(aff, dict):
                    continue
                pkg = aff.get("package") or {}
                eco_name = pkg.get("ecosystem")
                name = pkg.get("name")
                if eco_name not in targets or not isinstance(name, str):
                    continue
                eco = eco_ids[eco_name]
                es = aff.get("ecosystem_specific") if isinstance(aff.get("ecosystem_specific"), dict) else {}
                rating, rating_rank, note = entry_rating(family, es)
                kv = known[(eco, name)]
                versions = [v for v in aff.get("versions") or [] if isinstance(v, str)]
                kv.update(versions)
                if family == "Ubuntu":
                    for b in es.get("binaries") or []:
                        if isinstance(b, dict) and isinstance(b.get("binary_name"), str):
                            binaries.add((eco, b["binary_name"], name))
                ranges = [r for r in aff.get("ranges") or [] if isinstance(r, dict) and r.get("type") == "ECOSYSTEM"]
                if not ranges:
                    if versions:
                        stats.skipped_versions_only += 1
                    continue
                for r in ranges:
                    for intro, fixed, last in _segments(r.get("events") or []):
                        for v in (intro, fixed, last):
                            if v and v != "0":
                                kv.add(v)
                        rec_aff.append((eco, name, vid, intro, fixed, last, rating, rating_rank, note))
                        stats.per_ecosystem[eco_name] += 1
            if not rec_aff:
                continue
            next_vid += 1
            sev = record_severity(rec, family)
            kind = "advisory" if rid.startswith(ADVISORY_PREFIXES) else "issue"
            vuln_rows.append(
                (
                    vid,
                    rid,
                    kind,
                    " ".join(_aliases(rec)),
                    sev["vendor"],
                    sev["vendor_rank"],
                    sev["cvss"],
                    sev["cvss_rank"],
                    sev["vector"],
                    _summary(rec),
                    str(rec.get("published") or "")[:10],
                    _url(rec, family),
                )
            )
            aff_rows.extend(rec_aff)
            stats.records += 1
            if len(aff_rows) > 200_000:
                db.executemany("INSERT INTO affected VALUES (?,?,?,?,?,?,?,?,?)", aff_rows)
                stats.rows += len(aff_rows)
                aff_rows = []
        db.executemany("INSERT INTO vuln VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", vuln_rows)
        db.executemany("INSERT INTO affected VALUES (?,?,?,?,?,?,?,?,?)", aff_rows)
        stats.rows += len(aff_rows)
        db.commit()

    if log:
        log("Indexing rows and computing backport evidence ...")
    db.execute("CREATE INDEX affected_eco_pkg ON affected(eco, package)")
    evidence = []
    grouped: dict[tuple[int, str], dict[str, list[str]]] = {}
    eco_scheme = {i: scheme_for(n) for n, i in eco_ids.items()}
    for eco, pkg, fixed in db.execute("SELECT DISTINCT eco, package, fixed FROM affected WHERE fixed != ''"):
        scheme = eco_scheme[eco]
        by_up = grouped.get((eco, pkg))
        if by_up is None:
            by_up = defaultdict(list)
            for v in known.get((eco, pkg), ()):
                by_up[upstream_part(scheme, v)].append(v)
            grouped[(eco, pkg)] = by_up
        earlier = _backport_evidence(scheme, fixed, by_up.get(upstream_part(scheme, fixed), []))
        if earlier:
            evidence.append((eco, pkg, fixed, earlier))
    db.executemany("INSERT INTO backport VALUES (?,?,?,?)", evidence)
    db.executemany("INSERT INTO binaries VALUES (?,?,?)", sorted(binaries))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = {
        "schema_version": SCHEMA_VERSION,
        "generator": f"hcproof {__version__}",
        "built_utc": now,
        "ecosystems": json.dumps(sorted(ecosystems)),
        "snapshot_utc": min(snapshots[f].snapshot_utc for f in by_family),
        "rows": str(stats.rows),
        "records": str(stats.records),
    }
    for family in by_family:
        snap = snapshots[family]
        meta[f"snapshot_utc:{family}"] = snap.snapshot_utc
        meta[f"source_url:{family}"] = bulk_url(family)
        sha = snap.meta.get("sha256")
        if sha:
            meta[f"source_sha256:{family}"] = sha
    for eco_name, n in sorted(stats.per_ecosystem.items()):
        meta[f"rows:{eco_name}"] = str(n)
    db.executemany("INSERT INTO meta VALUES (?,?)", sorted(meta.items()))
    db.commit()
    db.execute("ANALYZE")
    db.commit()
    db.close()
    os.replace(tmp, out_path)
    stats.seconds = time.monotonic() - t0
    stats.bytes = out_path.stat().st_size
    return stats


def _backport_evidence(scheme: str, fixed: str, same_upstream: list[str]) -> str:
    """The earliest known build with the same upstream version as ``fixed`` but older.

    ``same_upstream`` holds every version the data mentions for this package and release
    (affected versions, introduced and fixed versions of any record) that has the same
    ``epoch:upstream`` part as ``fixed``. If the distro shipped e.g. 1:9.2p1-2 and later
    fixed the issue in 1:9.2p1-2+deb12u3, the fix is a distro revision of the same
    upstream version: a backport.
    """
    cands = [k for k in same_upstream if k != fixed and compare(scheme, k, fixed) < 0]
    if not cands:
        return ""
    return min(cands, key=cmp_to_key(lambda a, b: compare(scheme, a, b)))


# --------------------------------------------------------------------------- query


@dataclass
class Row:
    ecosystem: str
    package: str
    vuln_id: str
    kind: str
    aliases: list[str]
    introduced: str
    fixed: str
    last_affected: str
    backport_of: str
    rating: str
    rating_rank: int
    note: str
    vendor_severity: str
    vendor_rank: int
    cvss: str
    cvss_rank: int
    cvss_vector: str
    summary: str
    published: str
    url: str


class Index:
    def __init__(self, path: Path):
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(path)
        self.db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        # The file may come from a download: don't let its schema (views) call risky functions.
        self.db.execute("PRAGMA trusted_schema = OFF")
        self.meta = dict(self.db.execute("SELECT key, value FROM meta"))

    def close(self) -> None:
        self.db.close()

    @property
    def ecosystems(self) -> list[str]:
        return json.loads(self.meta.get("ecosystems", "[]"))

    def _eco_ids(self, ecosystems: list[str]) -> dict[int, str]:
        q = ",".join("?" * len(ecosystems))
        return dict(self.db.execute(f"SELECT eco, name FROM ecosystem WHERE name IN ({q})", ecosystems))

    def rows_for(self, ecosystems: list[str], packages: list[str]) -> list[Row]:
        if not packages or not ecosystems:
            return []
        ids = self._eco_ids(ecosystems)
        if not ids:
            return []
        out: list[Row] = []
        eq = ",".join("?" * len(ids))
        for i in range(0, len(packages), 400):
            chunk = packages[i : i + 400]
            pq = ",".join("?" * len(chunk))
            sql = (
                "SELECT a.eco, a.package, v.vuln_id, v.kind, v.aliases, a.introduced, a.fixed, a.last_affected, "
                "COALESCE(b.earlier, ''), a.rating, a.rating_rank, a.note, v.vendor_severity, v.vendor_rank, "
                "v.cvss, v.cvss_rank, v.cvss_vector, v.summary, v.published, v.url "
                "FROM affected a JOIN vuln v ON v.vid = a.vid "
                "LEFT JOIN backport b ON b.eco = a.eco AND b.package = a.package AND b.fixed = a.fixed "
                f"WHERE a.eco IN ({eq}) AND a.package IN ({pq})"
            )
            for r in self.db.execute(sql, [*ids, *chunk]):
                r = list(r)
                r[0] = ids[r[0]]
                r[4] = r[4].split() if r[4] else []
                out.append(Row(*r))
        return out

    def sources_for_binaries(self, ecosystems: list[str], binaries: list[str]) -> dict[str, set[str]]:
        out: dict[str, set[str]] = defaultdict(set)
        ids = self._eco_ids(ecosystems)
        if not ids:
            return out
        eq = ",".join("?" * len(ids))
        for i in range(0, len(binaries), 400):
            chunk = binaries[i : i + 400]
            pq = ",".join("?" * len(chunk))
            sql = f"SELECT binary, source FROM binaries WHERE eco IN ({eq}) AND binary IN ({pq})"
            for b, src in self.db.execute(sql, [*ids, *chunk]):
                out[b].add(src)
        return out


def local_index_path(cache: Path, snap: Snapshot) -> Path:
    return cache / "index" / f"{snap.family}-{snap.stamp}.sqlite"
