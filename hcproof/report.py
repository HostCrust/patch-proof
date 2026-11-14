"""Render a classification result as one self-contained, printable HTML file (and JSON)."""

from __future__ import annotations

import html
import json
import re
from collections import OrderedDict
from datetime import datetime, timezone

from . import __version__
from .classify import LABELS, Finding, Result
from .versions import compare

_EXPLAIN = {
    "open": "A fixed version is published by the distribution, but the installed package is older. Install the update.",
    "notrunning": "The fix is installed on disk in a newer kernel, but the server still runs an older, affected kernel. Reboot into the newest kernel.",
    "nofix": "The distribution's data lists the installed version as affected and no fix is published. This includes issues the distribution has deferred, not yet triaged, or decided not to fix. Track these, or mitigate where the issue applies to how the server is used.",
    "backport": "The installed package already contains the distribution's fix. The fix was backported into the same upstream version, so a scanner that only compares upstream version numbers may still report these as vulnerable.",
}

COMPACT_ABOVE = 150

_RANK_NAME = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "negligible", 0: "unrated"}

_CSS = """
:root{--bg:#ffffff;--fg:#1d2330;--muted:#5d6676;--line:#dfe3ea;--soft:#f5f7fa;--accent:#0f5bd8;
--open:#b42318;--open-bg:#fef3f2;--nr:#b54708;--nr-bg:#fffaeb;--nofix:#6941c6;--nofix-bg:#f4f3ff;
--bp:#067647;--bp-bg:#ecfdf3;--crit:#912018;--high:#b42318;--med:#b54708;--low:#475467;--neg:#667085}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:1080px;margin:0 auto;padding:28px 16px 40px;overflow-x:hidden}
.summary-line,.explain,.notes,ul.plain{overflow-wrap:anywhere}
a{color:var(--accent)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em}
.brand{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:600}
h1{font-size:26px;line-height:1.25;margin:4px 0 16px;overflow-wrap:anywhere}
h2{font-size:19px;margin:34px 0 6px}
h3{font-size:15px;margin:18px 0 6px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(230px,100%),1fr));gap:8px 20px;padding:14px 16px;background:var(--soft);border:1px solid var(--line);border-radius:10px}
.meta div{min-width:0}
.meta dt{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.meta dd{margin:0;overflow-wrap:anywhere}
.notes{margin:16px 0 0;padding:10px 14px;border-left:4px solid var(--nr);background:var(--nr-bg);border-radius:6px}
.notes p{margin:4px 0}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(200px,100%),1fr));gap:12px;margin:22px 0 8px}
.tile{border:1px solid var(--line);border-radius:10px;padding:14px 16px;border-top:5px solid var(--c);background:var(--bg)}
.tile .n{font-size:32px;font-weight:700;line-height:1.1;color:var(--c)}
.tile .l{font-weight:600;margin-top:2px}
.tile .s{color:var(--muted);font-size:13px}
.t-open{--c:var(--open)}.t-notrunning{--c:var(--nr)}.t-nofix{--c:var(--nofix)}.t-backport{--c:var(--bp)}
.summary-line{color:var(--muted);font-size:14px}
.explain{color:var(--muted);margin:0 0 10px}
details.pkg{border:1px solid var(--line);border-radius:8px;margin:8px 0;background:var(--bg)}
details.pkg>summary{cursor:pointer;overflow-wrap:anywhere;padding:9px 12px;display:flex;flex-wrap:wrap;gap:4px 14px;align-items:baseline;list-style:none}
details.pkg>summary::-webkit-details-marker{display:none}
details.pkg>summary::before{content:"\\25B8";color:var(--muted)}
details.pkg[open]>summary::before{content:"\\25BE"}
details.pkg[open]>summary{border-bottom:1px solid var(--line);background:var(--soft)}
.pkgname{font-weight:700}
.dim{color:var(--muted);font-size:13px}
.table-wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;vertical-align:top;padding:7px 10px;border-bottom:1px solid var(--line)}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600;background:var(--soft)}
td.ids{min-width:150px}
td.ids a,td.adv a,td.ver{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em}
td.ver{white-space:nowrap}
.ids a{font-weight:600}
.sev{display:inline-block;padding:1px 7px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap;border:1px solid currentColor}
.r5{color:var(--crit)}.r4{color:var(--high)}.r3{color:var(--med)}.r2{color:var(--low)}.r1,.r0{color:var(--neg)}
.note{display:block;color:var(--muted);font-size:12.5px}
.empty{color:var(--muted);font-style:italic}
.toolbar{margin:6px 0 0}
.toolbar button{font:inherit;font-size:13px;padding:4px 10px;border:1px solid var(--line);background:var(--soft);border-radius:6px;cursor:pointer;color:var(--fg)}
.auditor{padding:14px 16px;border:1px solid var(--line);border-radius:10px;background:var(--soft)}
.auditor p{margin:0}
ul.plain{margin:6px 0;padding-left:20px}
footer{margin-top:36px;padding:18px 16px;border-radius:10px;background:#0b1f44;color:#fff;text-align:center;font-size:16px}
footer a{color:#fff;font-weight:700}
.fine{color:var(--muted);font-size:12.5px;margin-top:14px}
@media (max-width:640px){h1{font-size:22px}.tile .n{font-size:26px}th,td{padding:6px 7px}}
@media print{
  body{font-size:11.5px}main{max-width:none;padding:0}
  .toolbar{display:none}
  details.pkg{break-inside:avoid-page}
  footer{background:none;color:var(--fg);border:1px solid var(--line)}footer a{color:var(--fg)}
  a{color:var(--fg);text-decoration:none}
}
"""

_JS = """
function hcToggle(open){document.querySelectorAll('details.pkg').forEach(function(d){d.open=open;});}
window.addEventListener('beforeprint',function(){hcToggle(true);});
"""


def _e(text) -> str:
    return html.escape(str(text), quote=True)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _sev_badge(f: Finding) -> str:
    return f'<span class="sev r{f.rank}">{_e(f.severity)}</span>'


_ADVISORY_RE = re.compile(r"^(USN|DSA|DLA|DTSA|ALSA|RLSA|RXSA)-")


def id_url(vid: str, ecosystem: str) -> str:
    """A link to the distro's own page for an ID, falling back to osv.dev."""
    family = ecosystem.split(":")[0]
    if vid.startswith("CVE-"):
        if family == "Ubuntu":
            return f"https://ubuntu.com/security/{vid}"
        if family == "Debian":
            return f"https://security-tracker.debian.org/tracker/{vid}"
        return f"https://access.redhat.com/security/cve/{vid}"
    if vid.startswith("USN-"):
        return f"https://ubuntu.com/security/notices/{vid}"
    if vid.startswith(("DSA-", "DLA-", "DTSA-")):
        return f"https://security-tracker.debian.org/tracker/{vid}"
    if vid.startswith("ALSA-") and ":" in ecosystem:
        major = ecosystem.split(":")[1]
        return f"https://errata.almalinux.org/{major}/{vid.replace(':', '-')}.html"
    if vid.startswith(("RLSA-", "RXSA-")):
        return f"https://errata.rockylinux.org/{vid}"
    return f"https://osv.dev/vulnerability/{vid}"


def _group_badge(top: Finding) -> str:
    """Badge for a package group: the highest rating among its rows."""
    if not top.rank:
        return ""
    return f'<span class="sev r{top.rank}" title="highest in this package">{_e(top.severity)}</span>'


def _ids_cell(f: Finding) -> str:
    """The main ID links to the distro's page for it; other CVE IDs follow."""
    cves = [i for i in f.ids if i.startswith("CVE-")]
    others = [i for i in cves if i != f.key]
    out = f'<a href="{_e(f.url)}">{_e(f.key)}</a>'
    if others:
        out += f'<span class="note">{_e(", ".join(others[:3]))}{" ..." if len(others) > 3 else ""}</span>'
    return out


def _advisory_cell(f: Finding, ecosystem: str, limit: int = 2) -> str:
    advs = [i for i in f.ids if _ADVISORY_RE.match(i)]
    if not advs:
        return "-"
    return "<br>".join(f'<a href="{_e(id_url(a, ecosystem))}">{_e(a)}</a>' for a in advs[:limit])


def _group(findings: list[Finding]) -> "OrderedDict[str, list[Finding]]":
    top: dict[str, tuple] = {}
    for f in findings:
        top[f.package] = max(top.get(f.package, (0, 0.0)), (f.rank, f.cvss))
    groups: OrderedDict[str, list[Finding]] = OrderedDict()
    for f in findings:  # already sorted by severity within each class
        groups.setdefault(f.package, []).append(f)
    return OrderedDict(sorted(groups.items(), key=lambda kv: (tuple(-x for x in top[kv[0]]), kv[0])))


def _max_version(scheme: str, versions: list[str]) -> str:
    best = ""
    for v in versions:
        if v and (not best or compare(scheme, v, best) > 0):
            best = v
    return best


def _class_section(result: Result, cls: str, open_default: bool) -> str:
    findings = result.by_class(cls)
    n_ids, n_pkgs = result.count(cls)
    head = f'<h2 id="{cls}">{_e(LABELS[cls])} <span class="dim">({n_ids:,} in {n_pkgs} package{"s" if n_pkgs != 1 else ""})</span></h2>'
    parts = [head, f'<p class="explain">{_e(_EXPLAIN[cls])}</p>']
    if cls == "notrunning":
        parts.append(_reboot_block(result))
    if not findings:
        parts.append('<p class="empty">None.</p>')
        return "\n".join(parts)
    scheme = result.inventory.scheme
    for pkg, items in _group(findings).items():
        first = items[0]
        top = max(items, key=lambda f: (f.rank, f.cvss))
        if cls == "open":
            need = _max_version(scheme, [f.fixed for f in items])
            action = f"update to {_e(need)} or later" if need else ""
            if need and all(f.via_pro for f in items):
                action += " (Ubuntu Pro)"
        elif cls == "notrunning":
            action = f"running {_e(first.running)}, installed {_e(first.installed)}"
        elif cls == "backport":
            action = "fixed by distro patches"
        else:
            action = "no fix published"
        bins = ", ".join(first.binaries[:6]) + (f" and {len(first.binaries) - 6} more" if len(first.binaries) > 6 else "")
        installed = first.running if (first.is_kernel and cls != "notrunning" and first.running) else first.installed
        summary = (
            f'<summary><span class="pkgname">{_e(pkg)}</span>'
            f'<span class="mono">{_e(installed)}</span>'
            f'<span>{len(items):,} {"vulnerability" if len(items) == 1 else "vulnerabilities"}</span>'
            f"{_group_badge(top)}"
            f'<span class="dim">{action}</span>'
            f'<span class="dim">{"kernel" if first.is_kernel else "binaries: " + _e(bins)}</span></summary>'
        )
        rows = []
        eco = result.inventory.ecosystem
        # Very large groups (usually the kernel) are listed without summaries to keep
        # the file small; every row still links to the distro's page.
        compact = len(items) > COMPACT_ABOVE
        for f in items:
            fixed_cell = _e(f.fixed) if f.fixed else '<span class="dim">none yet</span>'
            if cls == "backport" and f.backport_of and not compact:
                fixed_cell += f'<span class="note">distro patch; earlier build {_e(f.backport_of)} has the same upstream version</span>'
            notes = "".join(f'<span class="note">{_e(n)}</span>' for n in f.notes)
            summary_cell = "" if compact else f"<td>{_e(f.summary)}{notes}</td>"
            rows.append(
                f'<tr><td class="ids">{_ids_cell(f)}</td><td>{_sev_badge(f)}</td>'
                f'<td class="ver">{fixed_cell}</td>{summary_cell}'
                f'<td class="adv">{_advisory_cell(f, eco, 1 if compact else 2)}</td></tr>'
            )
        lead = (
            f'<p class="dim" style="margin:8px 12px">{len(items)} rows: summaries are left out for groups this large. '
            "Each ID links to the distro's page.</p>"
            if compact
            else ""
        )
        table = (
            lead
            + '<div class="table-wrap"><table><thead><tr><th>Vulnerability</th><th>Severity</th><th>Fixed version</th>'
            + ("" if compact else "<th>Summary</th>")
            + "<th>Advisory</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></div>"
        )
        parts.append(f'<details class="pkg"{" open" if open_default else ""}>{summary}{table}</details>')
    return "\n".join(parts)


def _reboot_block(result: Result) -> str:
    inv = result.inventory
    k = result.kernel
    out = []
    if k.running_version and k.newest_version and k.newest_version != k.running_version:
        out.append(
            f"<p>Running kernel <code>{_e(k.running_version)}</code>; newest installed kernel "
            f"<code>{_e(k.newest_version)}</code>. Reboot into the newest kernel to run the fixes below.</p>"
        )
    if inv.reboot_required:
        pkgs = ", ".join(sorted(set(inv.reboot_packages))) or "not listed"
        out.append(
            "<p>The system's reboot-required flag is set. Packages that asked for a reboot: "
            f"<code>{_e(pkgs)}</code>. Fixes in these packages may not be active until a reboot "
            "(or a service restart for libraries such as libc6).</p>"
        )
    return "\n".join(out)


def _auditor_note(result: Result, label: str, generated: str) -> str:
    inv = result.inventory
    meta = result.index_meta
    family = inv.ecosystem.split(":")[0]
    snap = meta.get(f"snapshot_utc:{family}", meta.get("snapshot_utc", "unknown"))
    c = {cls: result.count(cls)[0] for cls in ("open", "notrunning", "nofix", "backport", "fixed")}
    match_on = "source package" if inv.scheme == "dpkg" else "binary package"
    third = len(result.third_party)
    kernel = (
        f"the running kernel ({result.kernel.running_version}) was checked against the kernel source package "
        f"'{result.kernel.source}'"
        if result.kernel.running_version
        else "the running kernel could not be tied to a distro package"
    )
    gaps = " ".join(result.warnings)
    text = (
        f"On {generated}, HostCrust Patch Proof {__version__} checked the {len(inv.installed_packages):,} installed packages "
        f"of host \"{label}\" ({inv.pretty_name}) against {family} security data published through OSV.dev "
        f"(snapshot {snap}). Packages were matched by {match_on} name and versions were compared with "
        f"{inv.scheme} version rules; {kernel}. The input inventory has SHA-256 {inv.sha256}; the same input and "
        f"data snapshot reproduce this report. Result: {c['open']:,} vulnerabilities have a published fix that is not "
        f"installed; {c['notrunning']:,} are fixed in an installed kernel that is not running yet; {c['nofix']:,} have no "
        f"distro fix yet; {c['backport'] + c['fixed']:,} are fixed, {c['backport']:,} of them by distro backports that "
        "version-string scanners commonly misreport. Limits: only distro packages were assessed; "
        f"{third} package groups built outside the distro were listed but not assessed; containers, language "
        "packages, configuration and live kernel patching are out of scope; results are only as current as the "
        "data snapshot, and the distro's data decides what counts as affected and fixed."
        + (f" Data notes: {gaps}" if gaps else "")
    )
    return f'<div class="auditor"><p>{_e(text)}</p></div>'


def render_html(result: Result, label: str, generated: str | None = None) -> str:
    inv = result.inventory
    meta = result.index_meta
    generated = generated or _now_utc()
    family = inv.ecosystem.split(":")[0]
    snap = meta.get(f"snapshot_utc:{family}", meta.get("snapshot_utc", "unknown"))
    k = result.kernel
    kernel_text = inv.kernel_release or "unknown (not in the input)"
    if k.running_version:
        kernel_text += f" (package {k.running_version})"

    tiles = []
    for cls, title in (
        ("open", "Open, fix available"),
        ("backport", "Fixed by backport"),
        ("notrunning", "Patched, not running"),
        ("nofix", "No distro fix yet"),
    ):
        n, p = result.count(cls)
        sub = f"in {p} package{'s' if p != 1 else ''}"
        if cls == "notrunning" and inv.reboot_required:
            sub += " · reboot flag set"
        if cls == "open":
            pro = len({f.key for f in result.by_class("open") if f.via_pro})
            if pro:
                sub += f" · {pro} need Ubuntu Pro"
        tiles.append(
            f'<a class="tile t-{cls}" href="#{cls}" style="text-decoration:none;color:inherit">'
            f'<div class="n">{n:,}</div><div class="l">{_e(title)}</div><div class="s">{_e(sub)}</div></a>'
        )

    fixed_n, fixed_p = result.count("fixed")
    assessed = len(result.subjects)
    summary_line = (
        f"Also fixed (normal updates, not backports): {fixed_n:,} vulnerabilities. "
        f"{len(inv.installed_packages):,} installed packages in {assessed + len(result.third_party):,} source groups; "
        f"{result.packages_with_data:,} groups have security data. Counts are distinct vulnerability IDs (CVE where one exists)."
    )

    notes = ""
    if result.warnings:
        notes = '<div class="notes">' + "".join(f"<p>{_e(w)}</p>" for w in result.warnings) + "</div>"

    total_rows = len([f for f in result.findings if f.cls != "fixed"])
    sections = []
    for cls in ("open", "notrunning", "nofix", "backport"):
        sections.append(_class_section(result, cls, open_default=len(result.by_class(cls)) <= 25))

    third = ""
    if result.third_party:
        items = []
        for s in sorted(result.third_party, key=lambda s: s.name):
            flag = " (the distro has security data for a package of this name)" if s.name in result.third_party_with_data else ""
            items.append(
                f"<li><span class=\"pkgname\">{_e(s.name)}</span> <span class=\"mono\">{_e(s.version)}</span> "
                f"<span class=\"dim\">{_e(s.third_party)}{_e(flag)}</span></li>"
            )
        third = (
            '<h2 id="third-party">Not assessed: packages from outside the distro</h2>'
            '<p class="explain">These versions carry markers of a third-party repository or local build. The distro\'s '
            "fix data does not describe them, so no claim is made either way. Check them with their vendor.</p>"
            f'<ul class="plain">{"".join(items)}</ul>'
        )

    data_line = (
        f"OSV.dev {family} data, snapshot {snap}"
        + (f"; bulk file SHA-256 {meta[f'source_sha256:{family}']}" if meta.get(f"source_sha256:{family}") else "")
    )

    body = f"""
<main>
<div class="brand">HostCrust Patch Proof</div>
<h1>Patch Proof report: {_e(label)}</h1>
<dl class="meta">
<div><dt>Host label</dt><dd>{_e(label)}</dd></div>
<div><dt>Distribution</dt><dd>{_e(inv.pretty_name)} <span class="dim">({_e(inv.ecosystem)})</span></dd></div>
<div><dt>Running kernel</dt><dd class="mono">{_e(kernel_text)}</dd></div>
<div><dt>Report time</dt><dd>{_e(generated)}</dd></div>
<div><dt>Data snapshot</dt><dd>{_e(snap)}</dd></div>
<div><dt>Input SHA-256 (receipt)</dt><dd class="mono">{_e(inv.sha256)}</dd></div>
</dl>
{notes}
<div class="tiles">{"".join(tiles)}</div>
<p class="summary-line">{_e(summary_line)}</p>
<div class="toolbar"><button type="button" onclick="hcToggle(true)">Expand all</button> <button type="button" onclick="hcToggle(false)">Collapse all</button></div>
{"".join(sections)}
{third}
<h2 id="auditor">Auditor note</h2>
{_auditor_note(result, label, generated)}
<h2 id="method">How this was checked</h2>
<ul class="plain">
<li>Input: {"the HostCrust collector (read-only; package and OS metadata only)" if not inv.degraded else "a pasted package list (degraded mode)"}. No hostname or IP address is collected.</li>
<li>Data: {_e(data_line)}.</li>
<li>Matching: {"source package names (Debian/Ubuntu data is keyed by source package)" if inv.scheme == "dpkg" else "binary package names (AlmaLinux/Rocky Linux data is keyed by binary package)"}; versions compared with a tested implementation of {"dpkg" if inv.scheme == "dpkg" else "rpm"} ordering.</li>
<li>Fixed by backport: the installed version is at or above the distro's fixed version, the data shows an older distro build of the same upstream version (so the fix was a distro patch, not a new upstream release), and the server runs that same upstream version.</li>
<li>Severity: the distro's own rating and the CVSS v3 base score from the data, where present. Nothing is rated by this tool.</li>
<li>Kernel: kernel vulnerabilities are checked against the running kernel; packages built from the kernel source (headers, tools) are not reported separately.</li>
</ul>
<p class="fine">{total_rows} rows listed. Generated by HostCrust Patch Proof (hc-proof) {__version__}, Apache-2.0, github.com/HostCrust/patch-proof. This report makes no network requests.</p>
<footer>Want this every day for every server, with receipts? HostCrust (launching soon): <a href="https://hostcrust.com">hostcrust.com</a></footer>
</main>
"""
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:\">"
        f"<title>HostCrust Patch Proof: {_e(label)}</title><style>{_CSS}</style></head>"
        f"<body>{body}<script>{_JS}</script></body></html>\n"
    )


def to_json(result: Result, label: str, generated: str | None = None) -> dict:
    inv = result.inventory
    family = inv.ecosystem.split(":")[0]
    return {
        "tool": f"hcproof {__version__}",
        "label": label,
        "generated_utc": generated or _now_utc(),
        "distribution": inv.pretty_name,
        "ecosystem": inv.ecosystem,
        "kernel": {
            "release": inv.kernel_release,
            "running_version": result.kernel.running_version,
            "newest_installed": result.kernel.newest_version,
            "source": result.kernel.source,
            "reboot_required_flag": inv.reboot_required,
        },
        "snapshot_utc": result.index_meta.get(f"snapshot_utc:{family}", result.index_meta.get("snapshot_utc")),
        "input_sha256": inv.sha256,
        "degraded": inv.degraded,
        "counts": {cls: dict(zip(("ids", "packages"), result.count(cls))) for cls in ("open", "notrunning", "nofix", "backport", "fixed")},
        "warnings": result.warnings,
        "third_party": [{"package": s.name, "version": s.version, "reason": s.third_party} for s in result.third_party],
        "findings": [
            {
                "class": f.cls,
                "id": f.key,
                "ids": f.ids,
                "package": f.package,
                "installed": f.installed,
                "running": f.running,
                "fixed": f.fixed,
                "backport_of": f.backport_of,
                "severity": f.severity,
                "url": f.url,
                "notes": f.notes,
            }
            for f in result.findings
        ],
    }


def write_json(result: Result, label: str, path, generated: str | None = None) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_json(result, label, generated), fh, indent=1)
        fh.write("\n")
