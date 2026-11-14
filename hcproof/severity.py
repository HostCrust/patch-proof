"""Severity text from OSV data. Nothing here invents a rating.

Sources, in the order they are shown:
  * the distro's own rating: Ubuntu priority, Debian urgency, or the AlmaLinux / Rocky Linux
    advisory severity (the "Important:" prefix of the advisory title);
  * a CVSS v3.x base score, computed from the vector string in the record with the
    FIRST CVSS v3.1 formula. CVSS v4 vectors are shown as vectors only.

``rank`` is used for sorting only: 5 critical, 4 high, 3 medium, 2 low,
1 negligible/unimportant, 0 unrated.
"""

from __future__ import annotations

import math

_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

_WORD_RANK = {
    "critical": 5,
    "important": 4,
    "high": 4,
    "moderate": 3,
    "medium": 3,
    "low": 2,
    "negligible": 1,
    "unimportant": 1,
}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup (Appendix A of the specification)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Base score of a ``CVSS:3.x/...`` vector, or None if it is not a complete v3 vector."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = metrics["S"] == "C"
        if metrics["S"] not in ("U", "C"):
            return None
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[metrics["PR"]]
        av = _CVSS3_WEIGHTS["AV"][metrics["AV"]]
        ac = _CVSS3_WEIGHTS["AC"][metrics["AC"]]
        ui = _CVSS3_WEIGHTS["UI"][metrics["UI"]]
        c = _CVSS3_WEIGHTS["C"][metrics["C"]]
        i = _CVSS3_WEIGHTS["I"][metrics["I"]]
        a = _CVSS3_WEIGHTS["A"][metrics["A"]]
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def cvss_rank(score: float) -> int:
    if score >= 9.0:
        return 5
    if score >= 7.0:
        return 4
    if score >= 4.0:
        return 3
    if score > 0.0:
        return 2
    return 1


def word_rank(word: str) -> int:
    return _WORD_RANK.get(word.strip().lower(), 0)


_DISTRO_ADVISORY_SEVERITIES = ("Critical", "Important", "Moderate", "Low")


def record_severity(rec: dict, family: str) -> dict:
    """Record-level severity of an OSV record.

    Returns ``{"vendor": "Ubuntu: medium" | "", "vendor_rank": int,
    "cvss": "7.5" | "", "cvss_rank": int, "vector": str}``. ``cvss`` is empty when the
    record has no usable CVSS v3 vector (a CVSS v4-only record keeps its vector).
    """
    vendor_word = ""
    for sev in rec.get("severity") or []:
        if not isinstance(sev, dict):
            continue
        typ = sev.get("type")
        score = str(sev.get("score") or "")
        if (typ == "Ubuntu" or (typ is None and family == "Ubuntu")) and score.lower() in _WORD_RANK:
            vendor_word = vendor_word or score.lower()
    if not vendor_word and family in ("AlmaLinux", "Rocky Linux"):
        summary = str(rec.get("summary") or "")
        head = summary.split(":", 1)[0].strip()
        if ":" in summary and head in _DISTRO_ADVISORY_SEVERITIES:
            vendor_word = head

    out = {
        "vendor": f"{family}: {vendor_word}" if vendor_word else "",
        "vendor_rank": word_rank(vendor_word) if vendor_word else 0,
        "cvss": "",
        "cvss_rank": 0,
        "vector": "",
    }
    sevs = [s for s in rec.get("severity") or [] if isinstance(s, dict)]
    for s in sevs:
        if s.get("type") == "CVSS_V3":
            score = cvss3_base_score(str(s.get("score") or ""))
            if score is not None:
                out.update(cvss=f"{score:.1f}", cvss_rank=cvss_rank(score), vector=str(s["score"]))
                return out
    for s in sevs:
        if s.get("type") == "CVSS_V4":
            # CVSS v4 scores need FIRST's lookup tables; we keep the vector but show no number.
            out.update(vector=str(s.get("score") or ""))
            break
    return out


def display(vendor: str, cvss: str) -> str:
    """Combine a distro rating and a CVSS score into the text shown in reports."""
    parts = [p for p in (vendor, f"CVSS {cvss}" if cvss else "") if p]
    return " · ".join(parts) if parts else "unrated"


def combined_rank(entry_rank: int, vendor_rank: int, cvss_rank_: int) -> int:
    return entry_rank or vendor_rank or cvss_rank_


def entry_rating(family: str, ecosystem_specific: dict | None) -> tuple[str, int, str]:
    """Per-release rating from an ``affected[]`` entry: (display text, rank, note).

    Debian's urgency and Ubuntu's per-package priority live here. Debian's
    "end-of-life" is not a severity; it is returned as a note.
    """
    es = ecosystem_specific or {}
    if family == "Debian":
        urgency = str(es.get("urgency") or "").strip().lower().rstrip("*")
        if urgency in ("low", "medium", "high", "unimportant"):
            return f"Debian: {urgency}", word_rank(urgency), ""
        if urgency == "end-of-life":
            return "", 0, "Debian: no security support for this package in this release (end-of-life)"
        return "", 0, ""
    if family == "Ubuntu":
        prio = str(es.get("ubuntu_priority") or "").strip().lower()
        if prio in _WORD_RANK:
            return f"Ubuntu: {prio}", word_rank(prio), ""
    return "", 0, ""
