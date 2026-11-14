# Using the index from other programs

How to build a report from collector output inside another program (a web service, a CI job, a port to another language), using the SQLite index that `hc-proof index build` writes and that the daily GitHub Actions job publishes. Measured figures are from 14 Nov 2026 (OSV snapshots of that day) on an Apple M-series laptop; a typical VPS will be somewhat slower.

## 1. Two ways to integrate

**A. Call the CLI (recommended).** The Python package has no dependencies. Fetch the index once a day, then run the CLI against it; with `--index` it never touches the network and returns in under a second:

```sh
hc-proof index fetch --out /var/lib/hcproof/index.sqlite          # daily: download, verify the SHA-256, replace atomically
hc-proof report --index /var/lib/hcproof/index.sqlite \
    --input - --out "$html" --json "$json" --label "$label" < inventory.txt
# exit 0 = ok, 2 = bad input (show stderr to the user), 3 = data problem (log it)
```

From another language, start the process with an argument list (no shell), pass the label as an argument (the report HTML-escapes it), feed the inventory on stdin, and delete the HTML and JSON files after sending them. For a pasted `dpkg -l` / `rpm -qa` (degraded mode) add `--os ubuntu:24.04` (or `debian:12`, `almalinux:9`, `rocky:8`, ...).

**B. Port it.** Read the index directly (schema below), reimplement version comparison (section 4) and prove parity with the vectors, and follow the classification rules (section 5). Use the CLI's `--json` output on the fixtures in `tests/fixtures/` as the reference result.

## 2. Index schema (SQLite, schema_version 1)

The file is built in a temporary file and renamed into place, so readers never see a
partial index. Open it read-only (`file:/var/lib/hcproof/index.sqlite?mode=ro`).

### `meta(key TEXT PRIMARY KEY, value TEXT)`

| key | example |
|---|---|
| `schema_version` | `1` |
| `snapshot_utc` | `2026-11-13T16:03:25Z` (the oldest family snapshot in the file) |
| `snapshot_utc:<Family>` | `snapshot_utc:Ubuntu` = `2026-11-14T07:03:07Z` (Last-Modified of the OSV file; show this in the report) |
| `source_sha256:<Family>` | SHA-256 of the OSV `all.zip` the index was built from |
| `source_url:<Family>` | `https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip` |
| `built_utc`, `generator`, `ecosystems` (JSON list), `records`, `rows`, `rows:<ecosystem>` | build facts |

### `vulns` (a view; this is the shape to read)

`SELECT * FROM vulns WHERE ecosystem = ? AND package = ?` uses the index on
`affected(eco, package)`.

| column | meaning |
|---|---|
| `ecosystem` | OSV ecosystem: `Debian:12`, `Ubuntu:24.04:LTS`, `Ubuntu:Pro:24.04:LTS`, `AlmaLinux:9`, `Rocky Linux:9`, ... |
| `package` | Debian/Ubuntu: **source** package name. AlmaLinux/Rocky: **binary** package name. |
| `vuln_id` | OSV record ID: `UBUNTU-CVE-2024-6387`, `DEBIAN-CVE-2024-6387`, `DSA-5724-1`, `DLA-...`, `ALSA-2024:4312`, `RLSA-2024:4457` |
| `aliases` | space-separated: CVE IDs first (sorted), then related IDs (USN, DSA, ...). For `UBUNTU-CVE-X` / `DEBIAN-CVE-X` the first alias is `CVE-X`. |
| `introduced` | first affected version; `0` = since the beginning |
| `fixed` | first fixed version; empty string = no fix published |
| `severity` | display text from the data: `Ubuntu: high · CVSS 8.1`, `Debian: low`, `AlmaLinux: Important`, `CVSS 9.8`, or `unrated` |
| `summary` | one line, at most 160 characters |
| `published` | `YYYY-MM-DD` |
| `url` | distro page: the CVE page for per-CVE records, else the advisory |
| `last_affected` | rare alternative to `fixed` (affected up to and including this version) |
| `backport_of` | backport evidence: an older build of the same `epoch:upstream` version as `fixed` that the data lists for this package and release; empty if none |
| `note` | e.g. `Debian: no security support for this package in this release (end-of-life)` |
| `kind` | `issue` (one record per CVE: `UBUNTU-CVE-*`, `DEBIAN-CVE-*`) or `advisory` (`DSA`, `DLA`, `ALSA`, `RLSA`, `RXSA`; may list several CVEs) |
| `severity_rank` | for sorting: 5 critical, 4 high/important, 3 medium/moderate, 2 low, 1 negligible/unimportant, 0 unrated |

One row per (record, package, affected range). Most records have one range per package.

### Underlying tables

`ecosystem(eco, name)`, `vuln(vid, vuln_id, kind, aliases, vendor_severity, vendor_rank,
cvss, cvss_rank, cvss_vector, summary, published, url)`,
`affected(eco, package, vid, introduced, fixed, last_affected, rating, rating_rank, note)`
indexed on `(eco, package)`, `backport(eco, package, fixed, earlier)`, and
`binaries(eco, binary, source)` (Ubuntu binary-to-source map, for degraded mode). Integer
keys keep the file small; read through the view unless you need the raw columns.

### Not in the index

Ubuntu USN and Livepatch (LSN) records (the per-CVE records carry the same fixes and list
the USN IDs in `aliases`), AlmaLinux bug-fix and enhancement advisories (ALBA, ALEA),
withdrawn records, and Ubuntu FIPS/Realtime/BlueField ecosystems.

## 3. Keeping the index fresh

**Simplest:** download the prebuilt index the project publishes daily (`hc-proof index fetch --out FILE`, or `index.sqlite.gz` plus `index.sqlite.gz.sha256` from the `index-latest` release). It fetches only the small checksum file when nothing changed.

```cron
# /etc/cron.d/hcproof-index: fetch the published index
30 7 * * *  hcproof  flock -n /var/lib/hcproof/fetch.lock env HCPROOF_CACHE=/var/cache/hcproof hc-proof index fetch --out /var/lib/hcproof/index.sqlite >> /var/log/hcproof/index.log 2>&1
```

**Or build it yourself** from OSV.dev once a day (this is what the project's
`.github/workflows/index.yml` runs). OSV refreshes these files at least daily; the job
downloads only what changed (it compares the bucket's Last-Modified with the cache) and
replaces the index atomically.

```cron
# /etc/cron.d/hcproof-index: build from OSV.dev
30 7 * * *  hcproof  flock -n /var/lib/hcproof/build.lock env HCPROOF_CACHE=/var/cache/hcproof hc-proof index build --out /var/lib/hcproof/index.sqlite >> /var/log/hcproof/index.log 2>&1
```

`hc-proof` is on the PATH after `pipx install` (or use `python3 -m hcproof` from the folder
that contains `hcproof/`). Default ecosystems are the v1 scope: Debian 11/12, Ubuntu
20.04/22.04/24.04 LTS (plus their Ubuntu Pro data), AlmaLinux 8/9 and Rocky Linux 8/9. Add
others with `--ecosystems "Debian:13,Ubuntu:26.04:LTS"`. Exit code 0 = new index in place;
3 = download or data error (the previous index stays in place). Alert if `built_utc` in
`meta` is more than two days old.

## 4. Version comparison (for a port)

Both functions return -1, 0 or 1. Prove parity with **every** line of
`tests/vectors/dpkg.json` and `tests/vectors/rpm.json`, in both directions
(`cmp(b, a) == -cmp(a, b)`). The reference code is `hcproof/versions.py`. All character
classes are ASCII only.

**dpkg** (Debian, Ubuntu; from dpkg's `verrevcmp`):

1. Split `[epoch:]upstream[-revision]`: epoch is the digits before the first `:` (default
   0); revision is everything after the **last** `-` (default empty, which equals `0`).
2. Compare epochs as integers, then upstream, then revision with `verrevcmp`:
   - loop while either string has characters left:
     - compare the leading non-digit parts character by character with the weight
       `~` = -1, end of string = 0, letters = their ASCII code, any other character = ASCII + 256;
       the first difference decides;
     - then compare the leading digit runs as numbers (leading zeros ignored, any length);
       the first difference decides.
3. Consequences: `1.0~rc1 < 1.0 < 1.0a < 1.0+`, `1.001 == 1.1`, `1.0 == 1.0-0`,
   `+deb12u7 < +deb12u10`.

**rpm** (AlmaLinux, Rocky Linux; from `rpmvercmp`, as `rpm.labelCompare`):

1. Split `[epoch:]version[-release]` (release after the last `-`); compare epochs as
   integers (missing = 0), then version, then release with `rpmvercmp`. An empty release
   sorts before any release.
2. `rpmvercmp(a, b)`: if equal, 0. Loop: skip characters that are not ASCII letters/digits
   and not `~` or `^`. `~` sorts before everything (if only one side has `~`, that side is
   older). `^` sorts after the end of the string but before anything else. Then take the
   next segment: a run of digits if the first side starts with a digit, else a run of
   letters, from both sides. If the second side's segment is empty, numeric beats alpha
   (return 1 if numeric, else -1). Numeric segments: strip leading zeros, longer wins, then
   compare as strings; alpha segments compare as strings. When all segments match, the side
   with characters left over is newer.
3. Consequences: `el9 < el9_4`, `553.el8_10 < 553.5.1.el8_10`, `1.0^git1 > 1.0`, `2a < 2.0`.

Helpers: `upstream_part(v)` is `epoch:upstream` for dpkg (revision removed) and
`epoch:version` for rpm (release removed), with the epoch always written (`0:` if absent).

## 5. Classification (for a port)

Reference: `hcproof/classify.py`. Inputs are the parsed collector output (sections
`## os-release`, `## kernel`, `## reboot-required`, `## packages`; see `hcproof/inventory.py`)
and the index.

1. **Ecosystem** from `/etc/os-release`: `debian` + `12` -> `Debian:12`; `ubuntu` + `24.04` ->
   `Ubuntu:24.04:LTS` (LTS when the year is even and the month is 04), plus the companion
   `Ubuntu:Pro:24.04:LTS`; `almalinux` + `9.4` -> `AlmaLinux:9`; `rocky` + `8.10` -> `Rocky Linux:8`.
2. **Installed packages**: dpkg rows whose status ends in `installed`, `triggers-pending`,
   `triggers-awaited`, `half-configured` or `unpacked`; all rpm rows except `gpg-pubkey`.
   dpkg source: the `Source` column is empty (source = binary name, version = binary
   version), `name`, or `name (version)`.
3. **Subjects**: group installed packages by (source name, source version). Debian/Ubuntu
   look up `package = source name` and compare the **source version**. AlmaLinux/Rocky look
   up each binary name and compare that binary's `epoch:version-release`.
4. **Kernel** (special subject): dpkg kernel images are `linux-image-<release>` /
   `linux-image-unsigned-<release>` (release starts with a digit). The kernel source is the
   source of `linux-modules-<release>` (or `linux-headers-<release>`), else the image's
   source with `linux-signed[-arch]` -> `linux` and `linux-signed-X` -> `linux-X`. The
   running image is the one whose release equals `uname -r`; its exact version comes from
   `signature=Ubuntu <version>-<flavour> ...` (Ubuntu) or `build=... Debian <version> (...)`
   (Debian), else the image package version. Newest = highest image version of the same
   source. Every installed package whose source is a kernel source (or whose name starts with
   `linux-image-`, `linux-modules-`, `linux-headers-`, `linux-tools-`, `linux-cloud-tools-`,
   `linux-buildinfo-`, `linux-signed-`) is not evaluated on its own. RPM: kernels are the
   installed `kernel-core` (or `kernel`) packages from source `kernel`; running =
   `0:` + `uname -r` without the `.arch`; look up `kernel` and `kernel-core`; all binaries from
   source `kernel` are folded in.
5. **Third-party builds** are not evaluated (listed as "not assessed"): dpkg versions
   matching `deb\.sury\.org|\+0~20\d{6}`, `\+maria~`, `nodesource`, `pgdg` (any case),
   `~bpo\d`, `~(focal|jammy|noble|bullseye|bookworm|trixie|plucky|questing|resolute)\b`,
   `~(ubuntu|debian)[.-]\d`, `\.gbp[0-9a-f]{6}`, `~ppa\d|\+ppa\d`; rpm packages whose vendor is
   set and is not `AlmaLinux`, `Rocky Enterprise Software Foundation` or `Red Hat, Inc.`
   (`(none)` counts as third-party), or whose version matches `\.remi\b`, `\.ngx\b`, `PGDG`, `nodesource`.
6. **Range status** of one row for installed version `v` (rpm: if `fixed` or `v` contains
   `.module` and their major versions differ, the row does not apply):
   `v < introduced` (when introduced is not `0`) -> unaffected; `fixed` set -> `v < fixed` ?
   affected : fixed; `last_affected` set -> `v <= last_affected` ? affected : unaffected;
   otherwise affected (no fix).
7. **Group rows by issue key**: `issue` rows by their CVE (`aliases[0]` or the ID itself if it
   is a CVE); `advisory` rows under every CVE in `aliases` (or the advisory ID if none).
8. **Decide each key** from its rows. If any `issue` rows exist, use only those; else the
   advisories. Within one record (same `vuln_id`), any affected range makes it affected
   (fixed version = that range's `fixed`); else fixed if any range is fixed (take the
   highest such `fixed`). Across records, **fixed wins**; otherwise open with the lowest
   `fixed`; otherwise no fix. Decide the main ecosystem first; only if it is not fixed or
   open, look at the Ubuntu Pro rows: Pro fixed/open is reported with the note "Ubuntu Pro".
9. **Class**: open -> `open`; no fix -> `nofix`; fixed -> `backport` if `backport_of` is
   not empty and `upstream_part(v) == upstream_part(fixed)`, else `fixed`. Kernel: decide for
   the running version; if it is `open` and the newest installed kernel decides `fixed`, the
   class is `notrunning`. Count each class as distinct issue keys.
10. **Notes to show**: Debian 11 is incomplete; AlmaLinux/Rocky have no unfixed data; Rocky
   coverage is lower; Ubuntu 20.04 needs Pro for most new fixes; degraded mode; reboot-required
   flag and its packages.

## 6. Sizes and timings

| Item | Value |
|---|---|
| Prebuilt index download (`index fetch`, `report --prebuilt`) | **41 MB** (`gzip -9`), 212 MB unpacked |
| OSV download for `index build` (all four families) | 911 MB: Ubuntu 816 MB, Debian 82 MB, AlmaLinux 7 MB, Rocky Linux 6 MB. The Ubuntu file took about 5 minutes on our link. Only changed files are fetched. |
| Cache on disk | about 0.9 GB of zips (older snapshots are deleted after a successful download) |
| Index (v1 scope) | **212 MB** (41 MB gzipped), 2,402,091 rows from 111,528 records. Ubuntu 20.04/22.04/24.04 are 2.1 M of the rows (every kernel flavour has its own rows). Needs another 212 MB free while building. |
| Index build, data cached | **96–108 s**, peak memory 236 MB |
| Lookup latency | 300 per-package queries through the `vulns` view: 24 ms in total. The largest single package (`linux` on Ubuntu 24.04, 10,292 rows): 41 ms. |
| Full report via the CLI with the index | 0.4 s for the Ubuntu 24.04 fixture (690 installed packages), including HTML |
| Report HTML size | 3.7 MB for the Ubuntu sample, 1.9 MB for the Debian sample (kernel CVE lists dominate; groups over 150 rows omit summaries) |

## 7. Privacy rules if you run it as a service

- Do not store the inventory. Keep it in memory or a temp file only for the request, unless
  the user asks to save or email the report, with consent.
- The collector output has no hostname or IP; the user-supplied label is the only name.
- Do not log the request body. Logging the input's SHA-256 is fine; it is in the report anyway.
- The report is self-contained (inline CSS, a small inline script for expand/collapse, a
  restrictive CSP meta tag) and makes no network requests.
