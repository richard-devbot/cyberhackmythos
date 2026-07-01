"""Trivy — dependency vulnerabilities (SCA), IaC misconfig, and secrets."""

from __future__ import annotations

from ..findings import Category, Finding, Severity
from ..sandbox import SandboxResult
from .base import Scanner, load_json, norm_cwe


class TrivyScanner(Scanner):
    name = "trivy"
    binary = "trivy"
    category = Category.DEPENDENCY
    description = "Scans dependencies for known CVEs, plus IaC misconfigurations and embedded secrets."
    ok_returncodes = (0,)

    def build_command(self, target: str = ".") -> str:
        # HOME=/tmp for the cache; vuln DB is expected pre-baked (offline).
        return (
            f"HOME=/tmp trivy fs --quiet --no-progress --format json "
            f"--scanners vuln,misconfig,secret {target} || true"
        )

    def parse(self, result: SandboxResult) -> list[Finding]:
        data = load_json(result)
        if not isinstance(data, dict):
            return []
        findings: list[Finding] = []
        for res in data.get("Results", []) or []:
            target = res.get("Target")
            findings.extend(self._vulns(res, target))
            findings.extend(self._misconfigs(res, target))
            findings.extend(self._secrets(res, target))
        return findings

    def _vulns(self, res: dict, target: str | None) -> list[Finding]:
        out: list[Finding] = []
        for v in res.get("Vulnerabilities", []) or []:
            try:
                out.append(
                    Finding(
                        tool="trivy",
                        rule_id=v.get("VulnerabilityID", "CVE"),
                        title=(v.get("Title") or v.get("VulnerabilityID", ""))[:140],
                        severity=Severity.coerce(v.get("Severity")),
                        category=Category.DEPENDENCY,
                        message=v.get("Description", "")[:500],
                        file=target,
                        cve=v.get("VulnerabilityID"),
                        package=v.get("PkgName"),
                        installed_version=v.get("InstalledVersion"),
                        fixed_version=v.get("FixedVersion"),
                        cwe=norm_cwe(v.get("CweIDs")),
                        remediation=(
                            f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion')}"
                            if v.get("FixedVersion")
                            else None
                        ),
                    )
                )
            except Exception:
                continue
        return out

    def _misconfigs(self, res: dict, target: str | None) -> list[Finding]:
        out: list[Finding] = []
        for m in res.get("Misconfigurations", []) or []:
            try:
                cause = m.get("CauseMetadata", {}) or {}
                out.append(
                    Finding(
                        tool="trivy",
                        rule_id=m.get("ID", "misconfig"),
                        title=(m.get("Title") or m.get("ID", ""))[:140],
                        severity=Severity.coerce(m.get("Severity")),
                        category=Category.IAC,
                        message=m.get("Message", "") or m.get("Description", ""),
                        file=target,
                        line=cause.get("StartLine"),
                        remediation=m.get("Resolution"),
                    )
                )
            except Exception:
                continue
        return out

    def _secrets(self, res: dict, target: str | None) -> list[Finding]:
        out: list[Finding] = []
        for s in res.get("Secrets", []) or []:
            try:
                out.append(
                    Finding(
                        tool="trivy",
                        rule_id=s.get("RuleID", "secret"),
                        title=(s.get("Title") or s.get("RuleID", ""))[:140],
                        severity=Severity.coerce(s.get("Severity")) or Severity.HIGH,
                        category=Category.SECRET,
                        message="Embedded secret detected. Rotate and remove from source.",
                        file=target,
                        line=s.get("StartLine"),
                        cwe=["CWE-798"],
                    )
                )
            except Exception:
                continue
        return out
