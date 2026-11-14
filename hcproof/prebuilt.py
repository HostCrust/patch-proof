"""Download, verify and cache the prebuilt index published with each GitHub release.

A GitHub Actions job (``.github/workflows/index.yml``) rebuilds the index from OSV.dev
every day and publishes ``index.sqlite.gz`` plus ``index.sqlite.gz.sha256`` under the
release tag ``index-latest``. Downloading that file (about 41 MB) replaces the first-run
download of each distribution family's OSV data (816 MB for Ubuntu).

Layout of the cache (``hc-proof`` never writes anywhere else)::

    <cache>/prebuilt/<url-key>/index-<YYYYMMDDTHHMMSSZ>.sqlite   the verified index, named by its build time
    <cache>/prebuilt/<url-key>/meta.json                          URL, SHA-256 of the .gz, build and download times
    <cache>/prebuilt/<url-key>/checked                            mtime = last time we asked for a newer index

The SHA-256 file is published next to the index, so the check catches a truncated or
corrupted download. It is not a signature: it does not protect against someone who can
replace both files on the release. The index is only ever opened read-only as SQLite.
"""

from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .index import SCHEMA_VERSION
from .osv import USER_AGENT, DataError, cache_dir

DEFAULT_INDEX_URL = "https://github.com/HostCrust/patch-proof/releases/download/index-latest/index.sqlite.gz"
ENV_INDEX_URL = "HCPROOF_INDEX_URL"
# Hard limits, far above today's sizes (about 41 MB compressed, about 212 MB unpacked).
MAX_GZ_BYTES = 1 << 30
MAX_INDEX_BYTES = 4 << 30
# Warn when the cached index is older than this (the daily rebuild may have stopped).
STALE_AFTER_HOURS = 72
STAMP_FORMAT = "%Y%m%dT%H%M%SZ"
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_LOOPBACK_NAMES = {"localhost"}


class ChecksumError(DataError):
    pass


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def resolve_url(url: str | None = None) -> str:
    """The URL to use: the argument, else ``$HCPROOF_INDEX_URL``, else the GitHub release."""
    return url or os.environ.get(ENV_INDEX_URL) or DEFAULT_INDEX_URL


def check_url(url: str) -> None:
    """Allow https anywhere, and plain http only to this machine (for mirrors and tests)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname:
        host = parts.hostname
        if host in _LOOPBACK_NAMES:
            return
        try:
            if ipaddress.ip_address(host).is_loopback:
                return
        except ValueError:
            pass
    raise ValueError(f"index URL must be https:// (or http:// to localhost): {url}")


class _NoDowngradeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects (GitHub sends release assets to a CDN), but never from https to http."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(req.full_url).scheme == "https" and urllib.parse.urlsplit(newurl).scheme != "https":
            raise DataError(f"refusing redirect from https to {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_NoDowngradeRedirect)


def _open(url: str, timeout: float = 60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return _OPENER.open(req, timeout=timeout)


def _url_key(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def _root(url: str) -> Path:
    return cache_dir() / "prebuilt" / _url_key(url)


def fetch_checksum(url: str) -> str:
    """Read ``<url>.sha256`` (``sha256sum`` format) and return the hex digest."""
    with _open(url + ".sha256") as resp:
        text = resp.read(4096).decode("ascii", errors="replace")
    token = text.split()[0].lower() if text.split() else ""
    if not _SHA_RE.match(token):
        raise DataError(f"{url}.sha256 does not contain a SHA-256 digest")
    return token


def _download(url: str, dest: Path, quiet: bool) -> tuple[str, int, str]:
    sha = hashlib.sha256()
    size = 0
    with _open(url) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        if total > MAX_GZ_BYTES:
            raise DataError(f"the index download is larger than {MAX_GZ_BYTES} bytes")
        last_modified = resp.headers.get("Last-Modified") or ""
        last_report = time.monotonic()
        with open(dest, "wb") as fh:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_GZ_BYTES:
                    raise DataError(f"the index download is larger than {MAX_GZ_BYTES} bytes")
                fh.write(chunk)
                sha.update(chunk)
                now = time.monotonic()
                if not quiet and total and now - last_report > 2:
                    _log(f"  {size / 1e6:,.0f} of {total / 1e6:,.0f} MB")
                    last_report = now
    if total and size != total:
        raise DataError(f"index download truncated ({size} of {total} bytes)")
    return sha.hexdigest(), size, last_modified


def _gunzip(src: Path, dest: Path) -> None:
    size = 0
    try:
        with gzip.open(src, "rb") as zin, open(dest, "wb") as out:
            while True:
                chunk = zin.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_INDEX_BYTES:
                    raise DataError(f"the index is larger than {MAX_INDEX_BYTES} bytes when unpacked")
                out.write(chunk)
    except (OSError, EOFError) as exc:
        raise DataError(f"the downloaded index is not a valid gzip file ({exc})") from exc


def validate(path: Path) -> dict:
    """Open ``path`` read-only and check it is an index this version can read. Returns its meta."""
    try:
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            db.execute("PRAGMA trusted_schema = OFF")
            meta = dict(db.execute("SELECT key, value FROM meta"))
            db.execute("SELECT 1 FROM vulns LIMIT 1").fetchall()
        finally:
            db.close()
    except sqlite3.DatabaseError as exc:
        raise DataError(f"the downloaded index is not a readable SQLite index ({exc})") from exc
    if meta.get("schema_version") != SCHEMA_VERSION:
        raise DataError(f"the downloaded index has schema version {meta.get('schema_version')!r}; this hc-proof reads {SCHEMA_VERSION}")
    try:
        ecosystems = json.loads(meta.get("ecosystems", "[]"))
    except ValueError:
        ecosystems = []
    if not ecosystems:
        raise DataError("the downloaded index lists no ecosystems")
    return meta


def _stamp(built_utc: str) -> str:
    try:
        when = datetime.strptime(built_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        when = datetime.now(timezone.utc)
    return when.strftime(STAMP_FORMAT)


def cached(url: str) -> tuple[Path, dict] | None:
    """The cached index for ``url`` and its meta.json, if both are present."""
    root = _root(url)
    try:
        info = json.loads((root / "meta.json").read_text())
    except (OSError, ValueError):
        return None
    path = root / str(info.get("file", ""))
    if not info.get("file") or not path.is_file():
        return None
    return path, info


def _install(url: str, quiet: bool) -> tuple[Path, dict]:
    root = _root(url)
    root.mkdir(parents=True, exist_ok=True)
    work = root / f"_download.{os.getpid()}"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    try:
        expected = fetch_checksum(url)
        gz = work / "index.sqlite.gz"
        if not quiet:
            _log(f"Downloading the prebuilt index from {url} ...")
        got, size, last_modified = _download(url, gz, quiet)
        if got != expected:
            # The publisher replaces the .gz and the .sha256 one after the other; a download
            # that straddles the two sees a mismatch. Ask for the checksum once more.
            expected = fetch_checksum(url)
            if got != expected:
                raise ChecksumError(f"SHA-256 mismatch for {url}: downloaded {got}, published {expected}")
        tmp = work / "index.sqlite"
        _gunzip(gz, tmp)
        meta = validate(tmp)
        built = meta.get("built_utc", "")
        final = root / f"index-{_stamp(built)}.sqlite"
        os.replace(tmp, final)
        info = {
            "url": url,
            "file": final.name,
            "sha256": got,
            "bytes_gz": size,
            "built_utc": built,
            "snapshot_utc": meta.get("snapshot_utc", ""),
            "release_last_modified": last_modified,
            "downloaded_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        meta_tmp = work / "meta.json"
        meta_tmp.write_text(json.dumps(info, indent=2))
        os.replace(meta_tmp, root / "meta.json")
        for old in root.glob("index-*.sqlite"):
            if old.name != final.name:
                old.unlink(missing_ok=True)
        return final, info
    finally:
        shutil.rmtree(work, ignore_errors=True)


def ensure_prebuilt(
    url: str | None = None, *, offline: bool = False, max_age_hours: float = 24, quiet: bool = False
) -> Path:
    """Return the path of a verified prebuilt index, downloading a newer one when due.

    * ``offline``: never touch the network; fail if nothing is cached.
    * ``max_age_hours``: if we asked for a newer index less than this long ago, do not ask again.
      When we do ask, only the small ``.sha256`` file is fetched unless the index changed.
    * On a network or data error, a previously cached index is used (with a warning).
    """
    url = resolve_url(url)
    check_url(url)
    have = cached(url)
    checked = _root(url) / "checked"
    if offline:
        if not have:
            raise DataError(f"no cached prebuilt index from {url}; run once without --offline")
        return _reuse(have, quiet)
    if have and checked.exists() and time.time() - checked.stat().st_mtime < max_age_hours * 3600:
        return _reuse(have, quiet)
    try:
        if have and fetch_checksum(url) == have[1].get("sha256"):
            path = have[0]
        else:
            path, info = _install(url, quiet)
            if not quiet:
                _log(f"  verified SHA-256 {info['sha256']}; index built {info['built_utc'] or 'at an unknown time'}")
    except (OSError, DataError) as exc:
        if have:
            if not quiet:
                _log(f"warning: could not refresh the prebuilt index ({exc}); using the cached copy built {have[1].get('built_utc') or '?'}")
            return _reuse(have, quiet=True)
        if isinstance(exc, DataError):
            raise
        raise DataError(f"could not download the prebuilt index from {url}: {exc}") from exc
    checked.parent.mkdir(parents=True, exist_ok=True)
    checked.touch()
    return _reuse(cached(url) or (path, {}), quiet)


def _reuse(have: tuple[Path, dict], quiet: bool) -> Path:
    path, info = have
    built = info.get("built_utc", "")
    if not quiet and built:
        try:
            age = datetime.now(timezone.utc) - datetime.strptime(built, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            age = None
        if age is not None and age.total_seconds() > STALE_AFTER_HOURS * 3600:
            _log(f"warning: the prebuilt index was built {age.days} days ago ({built}); the report shows its data snapshot")
    return path
