"""Bandit — Python-specific static analysis (SAST)."""

from __future__ import annotations

from ..findings import Category, Finding, Severity
from ..sandbox import SandboxResult
from .base import Scanner, load_json, norm_cwe


class BanditScanner(Scanner):
    name = "bandit"
    binary = "bandit"
    category = Category.SAST
    description = "Finds common security issues in Python code (shell injection, weak crypto, hardcoded secrets)."
    ok_returncodes = (0, 1)  # bandit exits 1 when issues are found

    def build_command(self, target: str = ".") -> str:
        return f"bandit -r {target} -f json -q || true"

    def parse(self, result: SandboxResult) -> list[Finding]:
        data = load_json(result)
        if not isinstance(data, dict):
            return []
        findings: list[Finding] = []
        for r in data.get("results", []):
            try:
                cwe_field = r.get("issue_cwe") or {}
                cwe_id = cwe_field.get("id") if isinstance(cwe_field, dict) else None
                findings.append(
                    Finding(
                        tool="bandit",
                        rule_id=r.get("test_id", "bandit"),
                        title=(r.get("test_name") or r.get("issue_text", ""))[:140],
                        severity=Severity.coerce(r.get("issue_severity")),
                        category=Category.SAST,
                        message=r.get("issue_text", ""),
                        file=r.get("filename"),
                        line=r.get("line_number"),
                        cwe=norm_cwe(f"CWE-{cwe_id}" if cwe_id else None),
                    )
                )
            except Exception:
                continue
        return findings
