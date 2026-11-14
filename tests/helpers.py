"""Test helpers: build a small index from hand-written OSV records."""

import json
import zipfile
from pathlib import Path

from hcproof.index import Index, build, with_companions
from hcproof.osv import Snapshot


def make_index(tmp: Path, family: str, records: list[dict], ecosystems: list[str]) -> Index:
    root = Path(tmp) / family / "20261114T000000Z"
    root.mkdir(parents=True, exist_ok=True)
    zpath = root / "all.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        for rec in records:
            z.writestr(f"{rec['id']}.json", json.dumps(rec))
    snap = Snapshot(family, "20261114T000000Z", zpath)
    out = Path(tmp) / f"{family}.sqlite"
    build(out, with_companions(ecosystems), {family: snap})
    return Index(out)


def rec(vid, affected, **extra):
    """An OSV record. ``affected`` is a list of (ecosystem, package, events, versions, ecosystem_specific)."""
    r = {"id": vid, "schema_version": "1.7.0", "modified": "2026-11-01T00:00:00Z", "published": "2024-07-01T00:00:00Z"}
    r.update(extra)
    r["affected"] = []
    for item in affected:
        eco, pkg, events = item[:3]
        versions = item[3] if len(item) > 3 else []
        es = item[4] if len(item) > 4 else None
        a = {"package": {"ecosystem": eco, "name": pkg}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}
        if versions:
            a["versions"] = versions
        if es:
            a["ecosystem_specific"] = es
        r["affected"].append(a)
    return r


def fixed(v):
    return [{"introduced": "0"}, {"fixed": v}]


NOFIX = [{"introduced": "0"}]


def collector(os_id, version_id, packages, kernel=None, reboot=False, reboot_pkgs=(), fmt="dpkg"):
    """Collector output text. ``packages`` rows are tab-joined as given."""
    lines = ["# hcproof-collector 1", "## os-release", f'ID="{os_id}"', f'VERSION_ID="{version_id}"',
             f'PRETTY_NAME="{os_id} {version_id}"', "## kernel"]
    for k, v in (kernel or {}).items():
        lines.append(f"{k}={v}")
    lines += ["## reboot-required", f"flag={'yes' if reboot else 'no'}"] + [f"pkg={p}" for p in reboot_pkgs]
    lines += ["## packages", f"format={fmt}"]
    lines += ["\t".join(row) for row in packages]
    lines.append("## end")
    return ("\n".join(lines) + "\n").encode()


def dpkg_row(name, version, source="", status="install ok installed", arch="amd64"):
    return (status, name, version, arch, source)
