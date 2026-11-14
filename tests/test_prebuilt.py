"""The prebuilt index download: checksum, cache, reuse, fallback. Uses a local HTTP server only."""

import contextlib
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from hcproof import cli, prebuilt
from hcproof.osv import DataError

from .helpers import collector, dpkg_row, fixed, make_index, rec

D = "Debian:12"
RECORDS = [
    rec("DEBIAN-CVE-2024-6387", [(D, "openssh", fixed("1:9.2p1-2+deb12u3"), ["1:9.2p1-2"])], upstream=["CVE-2024-6387"]),
    rec("DEBIAN-CVE-2025-26465", [(D, "openssh", fixed("1:9.2p1-2+deb12u5"), ["1:9.2p1-2"])], upstream=["CVE-2025-26465"]),
]
INVENTORY = collector("debian", "12", [dpkg_row("openssh-server", "1:9.2p1-2+deb12u3", "openssh")])


class _Server:
    """Serves ``files`` (path -> bytes) on 127.0.0.1 and counts requests per path."""

    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.hits: dict[str, int] = {}
        self.redirects: dict[str, str] = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.hits[self.path] = outer.hits.get(self.path, 0) + 1
                if self.path in outer.redirects:
                    self.send_response(302)
                    self.send_header("Location", outer.redirects[self.path])
                    self.end_headers()
                    return
                body = outer.files.get(self.path)
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Last-Modified", "Sat, 14 Nov 2026 08:00:00 GMT")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def publish(self, sqlite_path: Path, sha_override: str | None = None) -> str:
        gz = gzip.compress(Path(sqlite_path).read_bytes(), mtime=0)
        digest = sha_override or hashlib.sha256(gz).hexdigest()
        self.files["/index.sqlite.gz"] = gz
        self.files["/index.sqlite.gz.sha256"] = f"{digest}  index.sqlite.gz\n".encode()
        return self.base + "/index.sqlite.gz"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class PrebuiltTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        env = {"HCPROOF_CACHE": str(self.root / "cache")}
        self.env = mock.patch.dict(os.environ, env)
        self.env.start()
        os.environ.pop(prebuilt.ENV_INDEX_URL, None)
        self.server = _Server()
        index = make_index(self.root / "src", "Debian", RECORDS, [D])
        self.sqlite = index.path
        index.close()
        self.url = self.server.publish(self.sqlite)

    def tearDown(self):
        self.server.close()
        self.env.stop()
        self.tmp.cleanup()

    def get(self, **kw):
        kw.setdefault("quiet", True)
        return prebuilt.ensure_prebuilt(self.url, **kw)


class TestDownload(PrebuiltTestCase):
    def test_download_verify_cache_and_reuse(self):
        path = self.get()
        self.assertTrue(path.is_file())
        self.assertTrue(path.name.startswith("index-") and path.name.endswith(".sqlite"))
        self.assertEqual(path.read_bytes(), self.sqlite.read_bytes())
        info = json.loads((path.parent / "meta.json").read_text())
        self.assertEqual(info["sha256"], hashlib.sha256(self.server.files["/index.sqlite.gz"]).hexdigest())
        self.assertTrue(info["built_utc"])
        self.assertEqual(info["release_last_modified"], "Sat, 14 Nov 2026 08:00:00 GMT")
        before = dict(self.server.hits)
        self.assertEqual(self.get(), path)  # within 24 h: no request at all
        self.assertEqual(self.server.hits, before)

    def test_recheck_with_same_index_fetches_only_the_checksum(self):
        self.get()
        self.get(max_age_hours=0)
        self.assertEqual(self.server.hits["/index.sqlite.gz"], 1)
        self.assertEqual(self.server.hits["/index.sqlite.gz.sha256"], 2)

    def test_new_index_replaces_the_old_one(self):
        first = self.get()
        index = make_index(self.root / "src2", "Debian", RECORDS[:1], [D])
        index.close()
        self.server.publish(index.path)
        second = self.get(max_age_hours=0)
        self.assertEqual(second.read_bytes(), index.path.read_bytes())
        if second != first:
            self.assertFalse(first.exists())
        self.assertEqual(len(list(second.parent.glob("index-*.sqlite"))), 1)

    def test_checksum_mismatch_is_rejected(self):
        self.server.publish(self.sqlite, sha_override="0" * 64)
        with self.assertRaises(prebuilt.ChecksumError):
            self.get()
        self.assertIsNone(prebuilt.cached(self.url))
        self.assertEqual(self.server.hits["/index.sqlite.gz.sha256"], 2)  # asked twice before giving up

    def test_checksum_mismatch_keeps_the_cached_copy(self):
        path = self.get()
        self.server.files["/index.sqlite.gz"] = gzip.compress(b"tampered")
        self.server.files["/index.sqlite.gz.sha256"] = ("1" * 64 + "  index.sqlite.gz\n").encode()
        self.assertEqual(self.get(max_age_hours=0), path)
        self.assertEqual(path.read_bytes(), self.sqlite.read_bytes())

    def test_not_gzip_or_not_sqlite(self):
        for body in (b"not gzip at all", gzip.compress(b"not a database" * 100)):
            with self.subTest(body=body[:10]):
                self.server.files["/index.sqlite.gz"] = body
                self.server.files["/index.sqlite.gz.sha256"] = (hashlib.sha256(body).hexdigest() + "\n").encode()
                with self.assertRaises(DataError):
                    self.get(max_age_hours=0)
                self.assertIsNone(prebuilt.cached(self.url))

    def test_bad_checksum_file(self):
        self.server.files["/index.sqlite.gz.sha256"] = b"<html>not found</html>"
        with self.assertRaises(DataError):
            self.get()

    def test_size_limit(self):
        with mock.patch.object(prebuilt, "MAX_INDEX_BYTES", 1024):
            with self.assertRaises(DataError):
                self.get()

    def test_offline(self):
        with self.assertRaises(DataError):
            self.get(offline=True)
        path = self.get()
        self.server.close()
        self.server = _Server()  # nothing served; the old port is closed
        self.assertEqual(self.get(offline=True), path)

    def test_server_down_uses_the_cached_copy(self):
        path = self.get()
        self.server.files.clear()
        self.assertEqual(self.get(max_age_hours=0), path)

    def test_404_without_cache_is_an_error(self):
        self.server.files.clear()
        with self.assertRaises(DataError):
            self.get()


class TestUrlRules(unittest.TestCase):
    def test_allowed(self):
        for url in (prebuilt.DEFAULT_INDEX_URL, "https://mirror.example/index.sqlite.gz", "http://127.0.0.1:8080/i.gz",
                    "http://localhost/i.gz", "http://[::1]/i.gz"):
            prebuilt.check_url(url)

    def test_refused(self):
        for url in ("http://example.com/index.sqlite.gz", "ftp://example.com/x", "file:///etc/passwd", "index.sqlite.gz", "https:///x"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                prebuilt.check_url(url)

    def test_default_url_and_environment(self):
        with mock.patch.dict(os.environ, {prebuilt.ENV_INDEX_URL: "https://mirror.example/i.gz"}):
            self.assertEqual(prebuilt.resolve_url(), "https://mirror.example/i.gz")
            self.assertEqual(prebuilt.resolve_url("https://other.example/i.gz"), "https://other.example/i.gz")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                prebuilt.resolve_url(),
                "https://github.com/HostCrust/patch-proof/releases/download/index-latest/index.sqlite.gz",
            )

    def test_https_to_http_redirect_is_refused(self):
        handler = prebuilt._NoDowngradeRedirect()
        req = urllib.request.Request("https://github.com/x/index.sqlite.gz")
        with self.assertRaises(DataError):
            handler.redirect_request(req, None, 302, "Found", {}, "http://cdn.example/index.sqlite.gz")
        ok = handler.redirect_request(req, None, 302, "Found", {}, "https://cdn.example/index.sqlite.gz")
        self.assertEqual(ok.full_url, "https://cdn.example/index.sqlite.gz")


class TestCli(PrebuiltTestCase):
    def run_cli(self, *args):
        inv = self.root / "inventory.txt"
        inv.write_bytes(INVENTORY)
        out = self.root / "report.html"
        js = self.root / "report.json"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.main(["report", "--input", str(inv), "--out", str(out), "--json", str(js), *args])
        return code, out, js, err.getvalue()

    def test_report_with_index_url(self):
        code, out, js, err = self.run_cli("--index-url", self.url)
        self.assertEqual(code, 0, err)
        data = json.loads(js.read_text())
        self.assertIn("CVE-2024-6387", out.read_text())
        self.assertIn("Using the prebuilt index", err)
        keys = {(f["class"], f["id"]) for f in data["findings"]}
        self.assertIn(("backport", "CVE-2024-6387"), keys)
        self.assertIn(("open", "CVE-2025-26465"), keys)

    def test_default_source_reads_the_environment_url(self):
        with mock.patch.dict(os.environ, {prebuilt.ENV_INDEX_URL: self.url}):
            code, out, _, err = self.run_cli()
        self.assertEqual(code, 0, err)
        self.assertEqual(self.server.hits["/index.sqlite.gz"], 1)

    def test_default_source_falls_back_to_osv_data(self):
        self.server.files.clear()
        index = make_index(self.root / "osv", "Debian", RECORDS, [D])
        with mock.patch.dict(os.environ, {prebuilt.ENV_INDEX_URL: self.url}), \
                mock.patch.object(cli, "_family_index", return_value=index) as fam:
            code, out, _, err = self.run_cli()
        self.assertEqual(code, 0, err)
        fam.assert_called_once()
        self.assertIn("Falling back to OSV Debian data", err)

    def test_missing_ecosystem_falls_back_unless_the_url_was_given(self):
        ubuntu = collector("ubuntu", "24.04", [dpkg_row("openssh-server", "1:9.6p1-3ubuntu13.5", "openssh")])
        inv = self.root / "ubuntu.txt"
        inv.write_bytes(ubuntu)
        out = self.root / "u.html"
        index = make_index(self.root / "osv", "Ubuntu", [], ["Ubuntu:24.04:LTS"])
        with mock.patch.dict(os.environ, {prebuilt.ENV_INDEX_URL: self.url}), \
                mock.patch.object(cli, "_family_index", return_value=index) as fam, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(["report", "--input", str(inv), "--out", str(out)]), 0)
        fam.assert_called_once()
        self.assertIn("does not cover", err.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["report", "--input", str(inv), "--out", str(out), "--index-url", self.url]), 3)

    def test_explicit_url_errors_are_not_masked(self):
        self.server.files.clear()
        code, *_ = self.run_cli("--index-url", self.url)
        self.assertEqual(code, 3)
        code, *_ = self.run_cli("--index-url", "http://example.com/index.sqlite.gz")
        self.assertEqual(code, 2)

    def test_osv_flag_skips_the_prebuilt_index(self):
        index = make_index(self.root / "osv", "Debian", RECORDS, [D])
        with mock.patch.object(cli, "_family_index", return_value=index) as fam:
            code, *_ = self.run_cli("--osv")
        self.assertEqual(code, 0)
        fam.assert_called_once()
        self.assertNotIn("/index.sqlite.gz", self.server.hits)

    def test_index_fetch(self):
        out = self.root / "fetched" / "index.sqlite"
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["index", "fetch", "--out", str(out), "--index-url", self.url]), 0)
        self.assertEqual(out.read_bytes(), self.sqlite.read_bytes())

    def test_collect_script(self):
        root = Path(__file__).resolve().parent.parent
        out = subprocess.run([sys.executable, "-m", "hcproof", "collect", "--script"], cwd=root, capture_output=True, check=True).stdout
        self.assertEqual(out, (root / "collect.sh").read_bytes())

if __name__ == "__main__":
    unittest.main()
