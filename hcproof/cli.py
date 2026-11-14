"""The ``hc-proof`` command line."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from importlib import resources
from pathlib import Path

from . import __version__, prebuilt
from .classify import classify
from .index import (
    EXTRA_ECOSYSTEMS,
    SCOPE_ECOSYSTEMS,
    Index,
    build,
    local_ecosystems,
    local_index_path,
    with_companions,
)
from .inventory import InventoryError, parse_inventory, sanitise
from .osv import DataError, cache_dir, ensure_snapshot, family_of
from .report import render_html, write_json

# Approximate OSV bulk download sizes (November 2026), shown before a fallback download.
_FAMILY_MB = {"Ubuntu": 816, "Debian": 82, "AlmaLinux": 7, "Rocky Linux": 6}


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _read_input(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def cmd_collect(args: argparse.Namespace) -> int:
    script = resources.files("hcproof").joinpath("collect.sh").read_bytes()
    if args.script:
        sys.stdout.buffer.write(script)
        sys.stdout.flush()
        return 0
    proc = subprocess.run(["/bin/sh", "-s"], input=script, stdout=sys.stdout.buffer, check=False)
    return proc.returncode


def _family_index(family: str, args: argparse.Namespace) -> Index:
    snap = ensure_snapshot(family, offline=args.offline, max_age_hours=args.max_age)
    path = local_index_path(cache_dir(), snap)
    if not path.exists():
        _log(f"Building the local {family} index (once per data snapshot) ...")
        stats = build(path, local_ecosystems(family), {family: snap}, log=_log)
        _log(f"  {stats.rows:,} rows in {stats.seconds:.0f} s, {stats.bytes / 1e6:.0f} MB")
    return Index(path)


def _prebuilt_index(inv, family: str, args: argparse.Namespace) -> Index:
    """The prebuilt index (default), falling back to the family's OSV data when it can't be used."""
    explicit = bool(args.index_url)
    url = prebuilt.resolve_url(args.index_url)
    if args.offline:
        fallback = f"Trying cached OSV {family} data instead."
    else:
        fallback = (
            f"Falling back to OSV {family} data (about {_FAMILY_MB.get(family, 100):,} MB on the first run). "
            "Add --osv to skip the prebuilt index."
        )
    try:
        path = prebuilt.ensure_prebuilt(url, offline=args.offline, max_age_hours=args.max_age)
    except DataError as exc:
        if explicit:
            raise
        _log(f"hc-proof: the prebuilt index is not available ({exc}).")
        _log(fallback)
        return _family_index(family, args)
    index = Index(path)
    if inv.ecosystem not in index.ecosystems:
        index.close()
        if explicit:
            raise DataError(f"the index at {url} has no data for {inv.ecosystem}; try --osv")
        _log(f"The prebuilt index does not cover {inv.pretty_name} ({inv.ecosystem}).")
        _log(fallback)
        return _family_index(family, args)
    snap = index.meta.get(f"snapshot_utc:{family}", index.meta.get("snapshot_utc", "unknown"))
    _log(f"Using the prebuilt index built {index.meta.get('built_utc', '?')} (OSV {family} snapshot {snap}).")
    return index


def cmd_report(args: argparse.Namespace) -> int:
    t0 = time.monotonic()
    inv = parse_inventory(_read_input(args.input), args.os)
    if args.index:
        index = Index(Path(args.index))
    else:
        family = family_of(inv.ecosystem)
        if inv.ecosystem not in local_ecosystems(family):
            raise InventoryError(f"{inv.pretty_name} ({inv.ecosystem}) is not supported")
        if args.source == "osv":
            index = _family_index(family, args)
        else:
            index = _prebuilt_index(inv, family, args)
    try:
        result = classify(inv, index)
    finally:
        index.close()
    label = args.label or "unnamed host"
    Path(args.out).write_text(render_html(result, label), encoding="utf-8")
    if args.json:
        write_json(result, label, args.json)
    counts = ", ".join(f"{cls} {result.count(cls)[0]}" for cls in ("open", "notrunning", "nofix", "backport", "fixed"))
    _log(f"{inv.pretty_name}: {counts}. Wrote {args.out} in {time.monotonic() - t0:.1f} s.")
    return 0


def cmd_index_build(args: argparse.Namespace) -> int:
    ecos = list(SCOPE_ECOSYSTEMS)
    if args.ecosystems:
        ecos = [e.strip() for part in args.ecosystems for e in part.split(",") if e.strip()]
    allowed = set(SCOPE_ECOSYSTEMS + EXTRA_ECOSYSTEMS)
    unknown = [e for e in ecos if e not in allowed]
    if unknown:
        raise InventoryError(f"unsupported ecosystems: {', '.join(unknown)} (supported: {', '.join(sorted(allowed))})")
    ecos = with_companions(ecos)
    families = sorted({family_of(e) for e in ecos})
    snaps = {f: ensure_snapshot(f, offline=args.offline, max_age_hours=args.max_age) for f in families}
    stats = build(Path(args.out), ecos, snaps, log=_log)
    _log(
        f"Wrote {args.out}: {stats.records:,} records, {stats.rows:,} rows, "
        f"{stats.bytes / 1e6:.1f} MB in {stats.seconds:.0f} s."
    )
    return 0


def cmd_index_fetch(args: argparse.Namespace) -> int:
    path = prebuilt.ensure_prebuilt(args.index_url, offline=args.offline, max_age_hours=args.max_age)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + f".tmp{os.getpid()}")
    shutil.copyfile(path, tmp)
    os.replace(tmp, out)
    index = Index(out)
    try:
        meta = index.meta
    finally:
        index.close()
    _log(f"Wrote {out}: built {meta.get('built_utc', '?')}, ecosystems {', '.join(json.loads(meta.get('ecosystems', '[]')))}.")
    return 0


def cmd_sanitise(args: argparse.Namespace) -> int:
    text = _read_input(args.input).decode("utf-8", errors="replace")
    out = sanitise(text)
    if args.out == "-":
        sys.stdout.write(out)
    else:
        Path(args.out).write_text(out, encoding="utf-8")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hc-proof",
        description="HostCrust Patch Proof: a read-only, backport-aware CVE report for Linux servers.",
    )
    p.add_argument("--version", action="version", version=f"hc-proof {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="print the collector output for this machine (read-only)")
    c.add_argument("--script", action="store_true", help="print the collector script itself instead of running it (to read it, or pipe it to ssh)")
    c.set_defaults(func=cmd_collect)

    r = sub.add_parser("report", help="build an HTML report from collector output")
    r.add_argument("--input", required=True, help="collector output, or a pasted dpkg -l / rpm -qa ('-' for stdin)")
    r.add_argument("--out", required=True, help="HTML file to write")
    r.add_argument("--label", help="host label shown in the report (no hostname is collected)")
    r.add_argument("--os", help="for a pasted package list: debian:12, ubuntu:24.04, almalinux:9, rocky:9 ...")
    r.add_argument("--json", help="also write the result as JSON to this file")
    src = r.add_mutually_exclusive_group()
    src.add_argument(
        "--prebuilt", dest="source", action="store_const", const="prebuilt",
        help="use the prebuilt index from the project's GitHub release (default; about 41 MB, SHA-256 checked, cached)",
    )
    src.add_argument(
        "--index-url", metavar="URL",
        help=f"download the prebuilt index from this URL instead (https; a URL.sha256 file must sit next to it). Default: ${prebuilt.ENV_INDEX_URL} or the GitHub release",
    )
    src.add_argument(
        "--osv", dest="source", action="store_const", const="osv",
        help="download each distribution family's OSV data and build the index locally (Ubuntu: 816 MB on the first run)",
    )
    src.add_argument("--index", metavar="FILE", help="use this index file (e.g. one from 'index build' or 'index fetch'); no network")
    r.set_defaults(source="prebuilt")
    r.add_argument("--offline", action="store_true", help="use cached data only; never touch the network")
    r.add_argument("--max-age", type=float, default=24, metavar="HOURS", help="re-check for newer data after this long (default 24)")
    r.set_defaults(func=cmd_report)

    i = sub.add_parser("index", help="manage the SQLite index")
    isub = i.add_subparsers(dest="index_command", required=True)
    ib = isub.add_parser("build", help="build the compact index from OSV data")
    ib.add_argument("--out", required=True, help="SQLite file to write (replaced atomically)")
    ib.add_argument(
        "--ecosystems",
        nargs="*",
        help="OSV ecosystems, space or comma separated (default: the v1 scope; Ubuntu Pro data is added for Ubuntu LTS)",
    )
    ib.add_argument("--offline", action="store_true", help="use cached data only")
    ib.add_argument("--max-age", type=float, default=0, metavar="HOURS", help="re-check OSV for new data after this long (default 0: always)")
    ib.set_defaults(func=cmd_index_build)
    fb = isub.add_parser("fetch", help="download and verify the prebuilt index, and copy it to a file")
    fb.add_argument("--out", required=True, help="SQLite file to write (replaced atomically)")
    fb.add_argument("--index-url", metavar="URL", help=f"where to download from (default: ${prebuilt.ENV_INDEX_URL} or the GitHub release)")
    fb.add_argument("--offline", action="store_true", help="use the cached copy only")
    fb.add_argument("--max-age", type=float, default=0, metavar="HOURS", help="re-check for a newer index after this long (default 0: always)")
    fb.set_defaults(func=cmd_index_fetch)

    s = sub.add_parser("sanitise", help="reduce collector output to package and OS data (for sharing)")
    s.add_argument("input", help="collector output ('-' for stdin)")
    s.add_argument("out", nargs="?", default="-", help="where to write ('-' for stdout)")
    s.set_defaults(func=cmd_sanitise)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (InventoryError, ValueError) as exc:
        _log(f"hc-proof: {exc}")
        return 2
    except (DataError, OSError) as exc:
        _log(f"hc-proof: {exc}")
        return 3


if __name__ == "__main__":
    sys.exit(main())
