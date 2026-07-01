"""Normalized security-finding model shared by all scanners.

Every scanner, regardless of its native output format, produces :class:`Finding`
objects. This is the single contract the agent, the deduper, and the reporters
(SARIF/HTML in later phases) all speak, so adding a scanner never ripples outward.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
            Severity.UNKNOWN: 0,
        }[self]

    @classmethod
    def coerce(cls, value: str | None) -> "Severity":
        """Map a scanner's severity string onto our scale."""
        if not value:
            return cls.UNKNOWN
        v = value.strip().lower()
        aliases = {
            "critical": cls.CRITICAL,
            "error": cls.HIGH,
            "high": cls.HIGH,
            "moderate": cls.MEDIUM,
            "medium": cls.MEDIUM,
            "warning": cls.MEDIUM,
            "warn": cls.MEDIUM,
            "low": cls.LOW,
            "minor": cls.LOW,
            "note": cls.INFO,
            "info": cls.INFO,
            "informational": cls.INFO,
            "style": cls.INFO,
            "negligible": cls.INFO,
            "unknown": cls.UNKNOWN,
        }
        return aliases.get(v, cls.UNKNOWN)


class Category(str, Enum):
    SAST = "sast"
    SECRET = "secret"
    DEPENDENCY = "dependency"
    IAC = "iac"
    CONTAINER = "container"
    MISC = "misc"


@dataclass
class Finding:
    """A single normalized security finding."""

    tool: str
    rule_id: str
    title: str
    severity: Severity
    category: Category
    message: str = ""
    file: str | None = None
    line: int | None = None
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    cve: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    remediation: str | None = None
    # Threat-intelligence enrichment (Phase 2), populated by agent/intel.py.
    cvss_score: float | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_ransomware: bool = False
    priority: str | None = None  # act_now | attend | track

    def fingerprint(self) -> str:
        """Stable identity used for dedup.

        Dependency findings identify by (cve, package) so two scanners reporting
        the same CVE collapse. Everything else identifies by (rule, file, line).
        """
        if self.category == Category.DEPENDENCY and self.cve:
            basis = f"dep:{self.cve}:{(self.package or '').lower()}"
        else:
            basis = f"{self.category.value}:{self.rule_id}:{self.file}:{self.line}"
        return hashlib.sha1(basis.encode()).hexdigest()[:16]

    def match_key(self) -> str:
        """Line-independent identity for before/after patch comparison.

        A patch shifts line numbers, so verification must not treat "same issue,
        new line" as one resolved + one introduced. This key omits the line.
        """
        if self.category == Category.DEPENDENCY and self.cve:
            return f"dep:{self.cve.upper()}:{(self.package or '').lower()}"
        return f"{self.category.value}:{self.rule_id}:{self.file}"

    def to_dict(self) -> dict:
        d = {
            "tool": self.tool,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "cve": self.cve,
            "package": self.package,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "kev": self.kev or None,
            "kev_ransomware": self.kev_ransomware or None,
            "priority": self.priority,
            "fingerprint": self.fingerprint(),
        }
        # Note: keep numeric 0/0.0 (e.g. epss); only drop None/empty. The bool
        # fields are coerced to None above so they fall out here when false.
        return {k: v for k, v in d.items() if v is not None and v != [] and v != ""}


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate findings, keeping the highest-severity representative.

    When two tools report the same issue (same fingerprint) we keep the one with
    the higher severity, and merge CWE/OWASP tags and the set of reporting tools.
    """
    by_fp: dict[str, Finding] = {}
    tools_seen: dict[str, set[str]] = {}
    for f in findings:
        fp = f.fingerprint()
        tools_seen.setdefault(fp, set()).add(f.tool)
        existing = by_fp.get(fp)
        if existing is None:
            by_fp[fp] = f
            continue
        # Merge tag sets.
        merged_cwe = sorted(set(existing.cwe) | set(f.cwe))
        merged_owasp = sorted(set(existing.owasp) | set(f.owasp))
        winner = existing if existing.severity.rank >= f.severity.rank else f
        winner.cwe = merged_cwe
        winner.owasp = merged_owasp
        by_fp[fp] = winner
    # Record which tools flagged each finding.
    for fp, f in by_fp.items():
        seen = tools_seen[fp]
        if len(seen) > 1:
            f.tool = "+".join(sorted(seen))
    return sorted(by_fp.values(), key=lambda x: x.severity.rank, reverse=True)


def summarize(findings: list[Finding]) -> dict[str, int]:
    """Return a severity histogram."""
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    counts["total"] = len(findings)
    return counts


# ---------------------------------------------------------------------------
# SARIF 2.1.0 export (GitHub Code Scanning compatible)
# ---------------------------------------------------------------------------

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
    Severity.UNKNOWN: "none",
}


def to_sarif(findings: list[Finding], tool_name: str = "cyberhackmythos") -> str:
    """Serialize findings as a minimal, valid SARIF 2.1.0 document."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rules.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.title or f.rule_id},
                "properties": {
                    "security-severity": _security_severity(f.severity),
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                },
            },
        )
        result: dict = {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message or f.title},
            "properties": {"tool": f.tool, "category": f.category.value},
        }
        if f.file:
            region = {"startLine": f.line} if f.line else {}
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        **({"region": region} if region else {}),
                    }
                }
            ]
        results.append(result)

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/richard-devbot/cyberhackmythos",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _security_severity(sev: Severity) -> str:
    """CVSS-like 0-10 score GitHub uses to bucket SARIF results."""
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
        Severity.UNKNOWN: "0.0",
    }[sev]
