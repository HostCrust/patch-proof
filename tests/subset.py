"""Save and load a small slice of an index, so end-to-end tests run offline.

    hc-proof index build --ecosystems Ubuntu:24.04:LTS Debian:12 --out /tmp/combined.sqlite
    python -m tests.subset /tmp/combined.sqlite   # rewrite tests/fixtures/osv-subset.json.gz

The slice holds every index row for the packages in the fixture inventories, taken
from one OSV snapshot per family (recorded in its meta table).
"""

import gzip
import json
import sqlite3
import sys
from pathlib import Path

from hcproof import index as hindex
from hcproof.classify import build_subjects
from hcproof.inventory import parse_inventory

FIXTURES = Path(__file__).parent / "fixtures"
SUBSET = FIXTURES / "osv-subset.json.gz"
INVENTORIES = ["ubuntu-24.04-vm.txt", "debian-12-synthetic.txt"]


def dump(src: Path, ecosystems: list[str], packages: list[str], binaries: list[str]) -> dict:
    db = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    q = lambda n: ",".join("?" * n)  # noqa: E731
    ecos = db.execute(f"SELECT eco, name FROM ecosystem WHERE name IN ({q(len(ecosystems))})", ecosystems).fetchall()
    ids = [e for e, _ in ecos]
    aff = db.execute(
        f"SELECT * FROM affected WHERE eco IN ({q(len(ids))}) AND package IN ({q(len(packages))}) ORDER BY rowid",
        [*ids, *packages],
    ).fetchall()
    vids = sorted({r[2] for r in aff})
    vulns = []
    for i in range(0, len(vids), 500):
        chunk = vids[i : i + 500]
        vulns += db.execute(f"SELECT * FROM vuln WHERE vid IN ({q(len(chunk))}) ORDER BY vid", chunk).fetchall()
    bp = db.execute(
        f"SELECT * FROM backport WHERE eco IN ({q(len(ids))}) AND package IN ({q(len(packages))})", [*ids, *packages]
    ).fetchall()
    bins = db.execute(
        f"SELECT * FROM binaries WHERE eco IN ({q(len(ids))}) AND binary IN ({q(len(binaries))})", [*ids, *binaries]
    ).fetchall()
    meta = dict(db.execute("SELECT key, value FROM meta"))
    meta["ecosystems"] = json.dumps(sorted(ecosystems))
    meta["subset_of"] = "tests/fixtures inventories"
    db.close()
    return {"meta": meta, "ecosystem": ecos, "vuln": vulns, "affected": aff, "backport": bp, "binaries": bins}


def load(data: dict, out: Path) -> hindex.Index:
    out.unlink(missing_ok=True)
    db = sqlite3.connect(out)
    db.executescript(hindex._SCHEMA)
    db.executemany("INSERT INTO ecosystem VALUES (?,?)", data["ecosystem"])
    db.executemany("INSERT INTO vuln VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", data["vuln"])
    db.executemany("INSERT INTO affected VALUES (?,?,?,?,?,?,?,?,?)", data["affected"])
    db.execute("CREATE INDEX affected_eco_pkg ON affected(eco, package)")
    db.executemany("INSERT INTO backport VALUES (?,?,?,?)", data["backport"])
    db.executemany("INSERT INTO binaries VALUES (?,?,?)", data["binaries"])
    db.executemany("INSERT INTO meta VALUES (?,?)", sorted(data["meta"].items()))
    db.commit()
    db.close()
    return hindex.Index(out)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    src = Path(argv[0])
    packages, binaries, ecos = set(), set(), set()
    for name in INVENTORIES:
        inv = parse_inventory((FIXTURES / name).read_bytes())
        subjects, third, _ = build_subjects(inv)
        packages |= {n for s in subjects + third for n in s.match_names}
        binaries |= {p.name for p in inv.packages}
        ecos |= set(hindex.with_companions([inv.ecosystem]))
    data = dump(src, sorted(ecos), sorted(packages), sorted(binaries))
    missing = ecos - {name for _, name in data["ecosystem"]}
    if missing:
        print(f"{src} lacks ecosystems: {', '.join(sorted(missing))}", file=sys.stderr)
        return 2
    with gzip.open(SUBSET, "wt", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"))
    print(f"{SUBSET}: {len(data['affected'])} rows, {len(data['vuln'])} records, {SUBSET.stat().st_size / 1e6:.1f} MB", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
