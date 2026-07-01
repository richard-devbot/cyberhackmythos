"""Hadolint — Dockerfile linting / best-practice + security checks."""

from __future__ import annotations

from ..findings import Category, Finding, Severity
from ..sandbox import SandboxResult
from .base import Scanner, load_json


class HadolintScanner(Scanner):
    name = "hadolint"
    binary = "hadolint"
    category = Category.CONTAINER
    description = "Lints Dockerfiles for insecure and non-reproducible instructions."
    ok_returncodes = (0, 1)

    def build_command(self, target: str = ".") -> str:
        # Collect Dockerfiles under the target; emit [] when there are none so
        # the parser has valid JSON either way.
        return (
            f"files=$(find {target} -iname 'Dockerfile*' -type f 2>/dev/null); "
            f'if [ -n "$files" ]; then hadolint -f json $files; else echo "[]"; fi'
        )

    def parse(self, result: SandboxResult) -> list[Finding]:
        data = load_json(result)
        if not isinstance(data, list):
            return []
        findings: list[Finding] = []
        for r in data:
            try:
                code = r.get("code", "hadolint")
                findings.append(
                    Finding(
                        tool="hadolint",
                        rule_id=code,
                        title=r.get("message", code)[:140],
                        severity=Severity.coerce(r.get("level")),
                        category=Category.CONTAINER,
                        message=r.get("message", ""),
                        file=r.get("file"),
                        line=r.get("line"),
                    )
                )
            except Exception:
                continue
        return findings
