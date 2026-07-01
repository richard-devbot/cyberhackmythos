"""Semgrep — multi-language static analysis (SAST)."""

from __future__ import annotations

from ..findings import Category, Finding, Severity
from ..sandbox import SandboxResult
from .base import Scanner, as_str_list, load_json, norm_cwe


class SemgrepScanner(Scanner):
    name = "semgrep"
    binary = "semgrep"
    category = Category.SAST
    description = "Static analysis for injection, crypto misuse, unsafe APIs, and more across many languages."
    ok_returncodes = (0, 1)

    def build_command(self, target: str = ".") -> str:
        # HOME=/tmp: cache dir must be writable under the read-only rootfs.
        # Rules are expected to be pre-baked into the scanner image (offline).
        return (
            f"HOME=/tmp semgrep scan --json --quiet --disable-version-check "
            f"--config auto {target} || true"
        )

    def parse(self, result: SandboxResult) -> list[Finding]:
        data = load_json(result)
        if not isinstance(data, dict):
            return []
        findings: list[Finding] = []
        for r in data.get("results", []):
            try:
                extra = r.get("extra", {}) or {}
                meta = extra.get("metadata", {}) or {}
                message = extra.get("message", "") or ""
                rule_id = r.get("check_id", "semgrep-rule")
                findings.append(
                    Finding(
                        tool="semgrep",
                        rule_id=rule_id,
                        title=(message.split("\n")[0][:140] or rule_id),
                        severity=Severity.coerce(extra.get("severity")),
                        category=Category.SAST,
                        message=message,
                        file=r.get("path"),
                        line=(r.get("start", {}) or {}).get("line"),
                        cwe=norm_cwe(meta.get("cwe")),
                        owasp=as_str_list(meta.get("owasp")),
                    )
                )
            except Exception:
                continue
        return findings
