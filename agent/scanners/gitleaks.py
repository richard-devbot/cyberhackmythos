"""Gitleaks — hardcoded secret detection."""

from __future__ import annotations

from ..findings import Category, Finding, Severity
from ..sandbox import SandboxResult
from .base import Scanner, load_json


class GitleaksScanner(Scanner):
    name = "gitleaks"
    binary = "gitleaks"
    category = Category.SECRET
    description = "Detects hardcoded secrets: API keys, tokens, private keys, credentials."
    ok_returncodes = (0, 1)  # exits 1 when leaks are found

    def build_command(self, target: str = ".") -> str:
        # /dev/stdout report keeps everything in-process; --no-git scans the tree
        # as files rather than commit history.
        return (
            f"gitleaks detect --no-git --source {target} "
            f"--report-format json --report-path /dev/stdout --no-banner --exit-code 0 "
            f"2>/dev/null || true"
        )

    def parse(self, result: SandboxResult) -> list[Finding]:
        data = load_json(result)
        if not isinstance(data, list):
            return []
        findings: list[Finding] = []
        for r in data:
            try:
                rule_id = r.get("RuleID", "secret")
                desc = r.get("Description", rule_id)
                # Deliberately omit the secret value itself from the finding.
                findings.append(
                    Finding(
                        tool="gitleaks",
                        rule_id=rule_id,
                        title=desc[:140],
                        severity=Severity.HIGH,
                        category=Category.SECRET,
                        message=f"Potential secret ({desc}) detected. Rotate and remove from source.",
                        file=r.get("File"),
                        line=r.get("StartLine"),
                        cwe=["CWE-798"],  # Use of Hard-coded Credentials
                        remediation="Rotate the exposed credential and move it to a secret store / env var.",
                    )
                )
            except Exception:
                continue
        return findings
