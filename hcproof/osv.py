"""Download and cache OSV.dev bulk data (one ``all.zip`` per ecosystem family).

Layout of the cache (``hc-proof`` never writes anywhere else)::

    <cache>/osv/<Family>/<YYYYMMDDTHHMMSSZ>/all.zip     the bulk file, named by its Last-Modified time
    <cache>/osv/<Family>/<YYYYMMDDTHHMMSSZ>/meta.json   URL, size, hashes, download time
    <cache>/osv/<Family>/checked                        mtime = last time we asked OSV for a newer file
    <cache>/index/<Family>-<YYYYMMDDTHHMMSSZ>.sqlite    the local index built from that snapshot

``<cache>`` is ``$HCPROOF_CACHE`` if set, else the platform's user cache directory.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
FAMILIES = ("Debian", "Ubuntu", "AlmaLinux", "Rocky Linux")
USER_AGENT = f"hcproof/{__version__} (+https://hostcrust.com)"
STAMP_FORMAT = "%Y%m%dT%H%M%SZ"


class DataError(RuntimeError):
    pass


def cache_dir() -> Path:
    env = os.environ.get("HCPROOF_CACHE")
    if env:
        return Path(env).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "hcproof"
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "hcproof" / "Cache"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "hcproof"


def family_of(ecosystem: str) -> str:
    family = ecosystem.split(":", 1)[0]
    if family not in FAMILIES:
        raise DataError(f"unsupported ecosystem: {ecosystem}")
    return family


def bulk_url(family: str) -> str:
    return f"{OSV_BUCKET}/{urllib.parse.quote(family)}/all.zip"


@dataclass
class Snapshot:
    family: str
    stamp: str  # YYYYMMDDTHHMMSSZ (the bulk file's Last-Modified time)
    path: Path

    @property
    def when(self) -> datetime:
        return datetime.strptime(self.stamp, STAMP_FORMAT).replace(tzinfo=timezone.utc)

    @property
    def snapshot_utc(self) -> str:
        return self.when.strftime("%Y-%m-%dT%H:%M:%SZ")

    @property
    def meta(self) -> dict:
        try:
            return json.loads((self.path.parent / "meta.json").read_text())
        except (OSError, ValueError):
            return {}


def _family_dir(family: str) -> Path:
    return cache_dir() / "osv" / family


def latest_cached(family: str) -> Snapshot | None:
    root = _family_dir(family)
    if not root.is_dir():
        return None
    stamps = sorted(
        d.name for d in root.iterdir() if d.is_dir() and (d / "all.zip").is_file() and not d.name.startswith("_")
    )
    if not stamps:
        return None
    return Snapshot(family, stamps[-1], root / stamps[-1] / "all.zip")


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _request(url: str, method: str = "GET"):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=60)


def _stamp_from_header(value: str | None) -> str:
    if not value:
        raise DataError("OSV did not send a Last-Modified header; cannot date the snapshot")
    return email.utils.parsedate_to_datetime(value).astimezone(timezone.utc).strftime(STAMP_FORMAT)


def _download(family: str, quiet: bool = False) -> Snapshot:
    url = bulk_url(family)
    root = _family_dir(family)
    tmp_dir = root / "_download"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp = tmp_dir / "all.zip.part"
    md5 = hashlib.md5(usedforsecurity=False)
    sha = hashlib.sha256()
    size = 0
    with _request(url) as resp:
        stamp = _stamp_from_header(resp.headers.get("Last-Modified"))
        total = int(resp.headers.get("Content-Length") or 0)
        goog_hash = resp.headers.get_all("x-goog-hash") or []
        last_report = 0.0
        with open(tmp, "wb") as fh:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                fh.write(chunk)
                md5.update(chunk)
                sha.update(chunk)
                size += len(chunk)
                now = time.monotonic()
                if not quiet and total and now - last_report > 2:
                    _log(f"  {family}: {size / 1e6:,.0f} of {total / 1e6:,.0f} MB")
                    last_report = now
    if total and size != total:
        raise DataError(f"{family}: download truncated ({size} of {total} bytes)")
    expected_md5 = None
    for h in goog_hash:
        for part in h.split(","):
            k, _, v = part.strip().partition("=")
            if k == "md5":
                expected_md5 = base64.b64decode(v).hex()
    if expected_md5 and expected_md5 != md5.hexdigest():
        raise DataError(f"{family}: MD5 mismatch after download (expected {expected_md5})")
    try:
        with zipfile.ZipFile(tmp) as z:
            if not z.namelist():
                raise DataError(f"{family}: the downloaded file is an empty zip")
    except zipfile.BadZipFile as exc:
        raise DataError(f"{family}: the downloaded file is not a valid zip") from exc

    final_dir = root / stamp
    final_dir.mkdir(parents=True, exist_ok=True)
    final = final_dir / "all.zip"
    os.replace(tmp, final)
    (final_dir / "meta.json").write_text(
        json.dumps(
            {
                "url": url,
                "last_modified_utc": datetime.strptime(stamp, STAMP_FORMAT).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "downloaded_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "bytes": size,
                "sha256": sha.hexdigest(),
                "md5_verified": bool(expected_md5),
            },
            indent=2,
        )
    )
    shutil.rmtree(tmp_dir, ignore_errors=True)
    return Snapshot(family, stamp, final)


def _prune(family: str, keep: str) -> None:
    """Remove older snapshots of a family (and their local indexes)."""
    root = _family_dir(family)
    for d in root.iterdir():
        if d.is_dir() and not d.name.startswith("_") and d.name != keep and (d / "all.zip").exists():
            shutil.rmtree(d, ignore_errors=True)
    idx_root = cache_dir() / "index"
    if idx_root.is_dir():
        for f in idx_root.glob(f"{family}-*.sqlite"):
            if f.stem != f"{family}-{keep}":
                f.unlink(missing_ok=True)


def ensure_snapshot(family: str, *, offline: bool = False, max_age_hours: float = 24, quiet: bool = False) -> Snapshot:
    """Return a cached snapshot, downloading a newer one when due.

    * ``offline``: never touch the network; fail if nothing is cached.
    * ``max_age_hours``: if we asked OSV less than this long ago, do not ask again.
    """
    cached = latest_cached(family)
    checked = _family_dir(family) / "checked"
    if offline:
        if not cached:
            raise DataError(f"no cached OSV data for {family}; run once without --offline")
        return cached
    if cached and checked.exists() and time.time() - checked.stat().st_mtime < max_age_hours * 3600:
        return cached
    try:
        with _request(bulk_url(family), method="HEAD") as resp:
            remote_stamp = _stamp_from_header(resp.headers.get("Last-Modified"))
            remote_size = int(resp.headers.get("Content-Length") or 0)
        if cached and cached.stamp >= remote_stamp:
            snap = cached
        else:
            if not quiet:
                _log(f"Downloading OSV {family} data ({remote_size / 1e6:,.0f} MB) ...")
            snap = _download(family, quiet=quiet)
            _prune(family, keep=snap.stamp)
    except (OSError, DataError) as exc:
        if cached:
            if not quiet:
                _log(f"warning: could not refresh OSV {family} data ({exc}); using the cached snapshot {cached.snapshot_utc}")
            return cached
        raise DataError(f"could not download OSV {family} data: {exc}") from exc
    checked.parent.mkdir(parents=True, exist_ok=True)
    checked.touch()
    return snap


def iter_records(zip_path: Path, ecosystems: set[str] | None = None) -> Iterator[dict]:
    """Yield OSV records from a bulk zip, skipping files that cannot mention ``ecosystems``.

    The zip is untrusted input: it is only read as JSON, never executed or extracted.
    """
    needles = [json.dumps(e).encode() for e in ecosystems] if ecosystems else None
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            if not info.filename.endswith(".json") or info.file_size > 64 * 1024 * 1024:
                continue
            raw = z.read(info)
            if needles and not any(n in raw for n in needles):
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if isinstance(rec, dict) and isinstance(rec.get("id"), str):
                yield rec
