"""Agent tools for the Phase 2 intelligence layer.

Thin adapters that run enrichment / prioritization / STRIDE over the shared
findings store and hand the model back a report.
"""

from __future__ import annotations

from . import config
from .findings import dedupe, summarize
from .graph import build_risk_graph, priority_table, to_stride
from .intel import ThreatIntel
from .scanners.base import get_findings_store
from .tools import Tool

_intel: ThreatIntel | None = None


def _get_intel() -> ThreatIntel:
    global _intel
    if _intel is None:
        _intel = ThreatIntel()
    return _intel


def _enrich_handler() -> str:
    if not config.INTEL_ENABLED:
        return "Threat intelligence is disabled (OPENMYTHOS_INTEL_ENABLED=false)."
    findings = dedupe(get_findings_store())
    if not findings:
        return "No findings to enrich yet. Run scan_all first."
    cve_findings = [f for f in findings if f.cve]
    if not cve_findings:
        return "No CVE-bearing findings to enrich (enrichment applies to dependency CVEs)."
    _get_intel().enrich_findings(findings)
    counts: dict[str, int] = {}
    for f in findings:
        if f.priority:
            counts[f.priority] = counts.get(f.priority, 0) + 1
    hist = ", ".join(f"{k.replace('_', ' ')}={v}" for k, v in counts.items()) or "none"
    return (
        f"Enriched {len(cve_findings)} CVE findings with EPSS + CISA KEV + CVSS.\n"
        f"Priority breakdown: {hist}\n\n"
        f"{priority_table(findings)}"
    )


def _threat_report_handler() -> str:
    findings = dedupe(get_findings_store())
    if not findings:
        return "No findings yet. Run scan_all (and enrich_findings for CVEs) first."
    counts = summarize(findings)
    stride = to_stride(findings)
    lines = [
        "## Threat report",
        f"Total findings: {counts['total']} "
        f"(critical={counts['critical']}, high={counts['high']}, medium={counts['medium']}, "
        f"low={counts['low']}, info={counts['info']})",
        "",
        "### Prioritized findings",
        priority_table(findings),
        "",
        "### STRIDE breakdown",
    ]
    for cat, items in stride.items():
        if items:
            lines.append(f"- **{cat}**: {len(items)} — " + ", ".join(
                sorted({(f.cve or f.rule_id) for f in items})[:6]
            ))
    return "\n".join(lines)


def _risk_graph_handler() -> str:
    findings = dedupe(get_findings_store())
    graph = build_risk_graph(findings)
    return f"Dependency / finding risk map (Mermaid):\n\n```mermaid\n{graph}\n```"


def build_intel_tools() -> list[Tool]:
    return [
        Tool(
            name="enrich_findings",
            description=(
                "Enrich all CVE findings with EPSS (exploitation probability), CISA KEV "
                "(known-exploited status), and CVSS, then assign a transparent priority "
                "(act_now / attend / track). Run after scan_all."
            ),
            parameters={"type": "object", "properties": {}, "required": []},
            handler=_enrich_handler,
        ),
        Tool(
            name="threat_report",
            description=(
                "Produce a prioritized threat report over all findings: severity summary, "
                "ranked priority table (CVSS/EPSS/KEV), and a STRIDE breakdown."
            ),
            parameters={"type": "object", "properties": {}, "required": []},
            handler=_threat_report_handler,
        ),
        Tool(
            name="risk_graph",
            description=(
                "Render a Mermaid risk map of vulnerable dependencies/files and their "
                "issues, colored by priority."
            ),
            parameters={"type": "object", "properties": {}, "required": []},
            handler=_risk_graph_handler,
        ),
    ]
