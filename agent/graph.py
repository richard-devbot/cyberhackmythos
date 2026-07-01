"""Risk visualization and STRIDE categorization built from findings.

Two data-driven views over the finding set:

* ``build_risk_graph`` — a Mermaid diagram of vulnerable dependencies/files and
  their issues, colored by priority. This is a *risk map* of what the scanners
  actually found, not a full transitive dependency tree (that needs an SBOM from
  Syft — a documented follow-on).
* ``to_stride`` — buckets findings into the six STRIDE threat categories using
  their CWE first, then their scanner category as a fallback.
"""

from __future__ import annotations

import re

from .findings import Category, Finding

# STRIDE categories.
SPOOFING = "Spoofing"
TAMPERING = "Tampering"
REPUDIATION = "Repudiation"
INFO_DISCLOSURE = "Information Disclosure"
DOS = "Denial of Service"
ELEVATION = "Elevation of Privilege"
STRIDE_ORDER = [SPOOFING, TAMPERING, REPUDIATION, INFO_DISCLOSURE, DOS, ELEVATION]

# CWE -> STRIDE. Curated from the common weakness set OpenMythos will encounter.
_STRIDE_BY_CWE: dict[str, str] = {
    "CWE-287": SPOOFING, "CWE-290": SPOOFING, "CWE-384": SPOOFING, "CWE-346": SPOOFING,
    "CWE-89": TAMPERING, "CWE-78": TAMPERING, "CWE-79": TAMPERING, "CWE-94": TAMPERING,
    "CWE-22": TAMPERING, "CWE-434": TAMPERING, "CWE-502": TAMPERING, "CWE-918": TAMPERING,
    "CWE-778": REPUDIATION, "CWE-117": REPUDIATION,
    "CWE-200": INFO_DISCLOSURE, "CWE-798": INFO_DISCLOSURE, "CWE-311": INFO_DISCLOSURE,
    "CWE-312": INFO_DISCLOSURE, "CWE-522": INFO_DISCLOSURE, "CWE-259": INFO_DISCLOSURE,
    "CWE-400": DOS, "CWE-770": DOS, "CWE-834": DOS, "CWE-1333": DOS,
    "CWE-269": ELEVATION, "CWE-250": ELEVATION, "CWE-732": ELEVATION, "CWE-276": ELEVATION,
}

_CATEGORY_STRIDE: dict[Category, str] = {
    Category.SECRET: INFO_DISCLOSURE,
    Category.SAST: TAMPERING,
    Category.DEPENDENCY: ELEVATION,
    Category.IAC: ELEVATION,
    Category.CONTAINER: ELEVATION,
    Category.MISC: TAMPERING,
}


def stride_category(f: Finding) -> str:
    for cwe in f.cwe:
        if cwe in _STRIDE_BY_CWE:
            return _STRIDE_BY_CWE[cwe]
    return _CATEGORY_STRIDE.get(f.category, TAMPERING)


def to_stride(findings: list[Finding]) -> dict[str, list[Finding]]:
    buckets: dict[str, list[Finding]] = {k: [] for k in STRIDE_ORDER}
    for f in findings:
        buckets[stride_category(f)].append(f)
    return buckets


# ---------------------------------------------------------------------------
# Risk graph (Mermaid)
# ---------------------------------------------------------------------------

_PRIORITY_STYLE = {
    "act_now": "fill:#b71c1c,color:#fff",
    "attend": "fill:#ef6c00,color:#fff",
    "track": "fill:#2e7d32,color:#fff",
}


def _node_id(prefix: str, n: int) -> str:
    return f"{prefix}{n}"


def _sanitize(text: str) -> str:
    # Mermaid labels: strip quotes/brackets/newlines that break node syntax.
    return re.sub(r'["\[\]\n{}|]', " ", text or "").strip()[:60]


def build_risk_graph(findings: list[Finding], max_nodes: int = 40) -> str:
    """Render vulnerable dependencies/files -> issues as a Mermaid flowchart."""
    if not findings:
        return "flowchart LR\n    empty[No findings to graph]"

    # Rank so the most urgent items are the ones that survive the node cap.
    ranked = sorted(
        findings,
        key=lambda f: (_priority_rank(f.priority), f.severity.rank, f.epss or 0.0),
        reverse=True,
    )[:max_nodes]

    lines = ["flowchart LR", "    root([Codebase])"]
    styles: list[str] = []
    groups: dict[str, list[Finding]] = {}
    for f in ranked:
        key = f.package or f.file or "(unknown)"
        groups.setdefault(key, []).append(f)

    gi = 0
    fi = 0
    for group, items in groups.items():
        gid = _node_id("g", gi)
        gi += 1
        lines.append(f'    root --> {gid}["{_sanitize(group)}"]')
        for f in items:
            nid = _node_id("f", fi)
            fi += 1
            label = f.cve or f.rule_id
            sev = f.severity.value.upper()
            lines.append(f'    {gid} --> {nid}["{_sanitize(label)}<br/>{sev}"]')
            style = _PRIORITY_STYLE.get(f.priority or "")
            if style:
                styles.append(f"    style {nid} {style}")
    lines.extend(styles)
    if len(findings) > max_nodes:
        lines.append(f'    note[+{len(findings) - max_nodes} more findings omitted]')
    return "\n".join(lines)


def _priority_rank(priority: str | None) -> int:
    return {"act_now": 3, "attend": 2, "track": 1}.get(priority or "", 0)


def priority_table(findings: list[Finding], limit: int = 40) -> str:
    """A ranked, human-readable prioritization table."""
    if not findings:
        return "No findings."
    ranked = sorted(
        findings,
        key=lambda f: (_priority_rank(f.priority), f.severity.rank, f.epss or 0.0),
        reverse=True,
    )
    rows = ["| Priority | Severity | CVSS | EPSS | KEV | ID | Location |",
            "|---|---|---|---|---|---|---|"]
    for f in ranked[:limit]:
        epss = f"{f.epss:.0%}" if f.epss is not None else "-"
        cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "-"
        kev = "⚠️" if f.kev else "-"
        loc = f"{f.file}:{f.line}" if f.file else "-"
        pri = (f.priority or "-").replace("_", " ")
        ident = f.cve or f.rule_id
        rows.append(f"| {pri} | {f.severity.value} | {cvss} | {epss} | {kev} | {ident} | {loc} |")
    return "\n".join(rows)
