"""Verified remediation: prove a patch actually fixes the finding.

The rule OpenMythos enforces: **no unverified patches**. A generated fix is only
trustworthy if, after applying it, (a) the target finding is gone on re-scan and
(b) no new findings were introduced. This module runs that loop against an
isolated copy of the workspace so the original is never mutated.

Flow: snapshot workspace → apply diff in sandbox → re-scan with the same
scanners → compare finding sets by line-independent ``match_key`` → optional test
command → structured verdict.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field

from . import config
from .findings import Finding, Severity, dedupe
from .sandbox import Sandbox, get_sandbox
from .scanners.base import Scanner
from .tools import Tool

_PATCH_FILE = ".openmythos.patch"
_APPLY_OK = "__OPENMYTHOS_APPLIED_OK__"


@dataclass
class VerificationResult:
    applied: bool
    resolved: list[str] = field(default_factory=list)      # match_keys that disappeared
    introduced: list[Finding] = field(default_factory=list)  # ALL new findings
    target_resolved: bool | None = None
    remaining_targets: list[str] = field(default_factory=list)
    tests_passed: bool | None = None
    regression_floor: Severity = Severity.HIGH
    message: str = ""

    @property
    def blocking_regressions(self) -> list[Finding]:
        """New findings at or above the regression floor — these fail the patch.
        Strictly-lower-severity residuals are reported but non-blocking."""
        return [f for f in self.introduced if f.severity.rank >= self.regression_floor.rank]

    @property
    def residual_regressions(self) -> list[Finding]:
        return [f for f in self.introduced if f.severity.rank < self.regression_floor.rank]

    @property
    def verified(self) -> bool:
        """Verified when it applied, introduced no blocking regression, and (if a
        target was named) resolved that target; else resolved at least one finding."""
        if not self.applied or self.blocking_regressions:
            return False
        if self.tests_passed is False:
            return False
        if self.target_resolved is None:
            return bool(self.resolved)
        return self.target_resolved


def snapshot_workspace(src: str) -> str:
    """Copy the workspace into a throwaway dir so the original stays pristine."""
    dst = tempfile.mkdtemp(prefix="openmythos_verify_")
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            shutil.copytree(s, d)
        else:
            shutil.copy2(s, d)
    os.chmod(dst, 0o755)
    return dst


class RemediationVerifier:
    def __init__(self, sandbox: Sandbox | None = None) -> None:
        self.sandbox = sandbox or get_sandbox()

    def apply_patch(self, workdir: str, diff: str) -> tuple[bool, str]:
        """Apply a unified diff inside *workdir* (sandboxed). Tries git apply then patch."""
        with open(os.path.join(workdir, _PATCH_FILE), "w", encoding="utf-8") as fh:
            fh.write(diff if diff.endswith("\n") else diff + "\n")
        cmd = (
            f"(git apply --whitespace=nowarn {_PATCH_FILE} "
            f"|| patch -p1 --forward -i {_PATCH_FILE} "
            f"|| patch -p0 --forward -i {_PATCH_FILE}) "
            f"&& echo {_APPLY_OK}"
        )
        res = self.sandbox.run_capture(cmd, workdir)
        return (_APPLY_OK in res.stdout), (res.stdout + res.stderr)

    def verify(
        self,
        *,
        workspace_dir: str,
        diff: str,
        scanners: list[Scanner],
        baseline: list[Finding],
        target_keys: list[str] | None = None,
        test_command: str | None = None,
    ) -> VerificationResult:
        copy = snapshot_workspace(workspace_dir)
        try:
            applied, apply_out = self.apply_patch(copy, diff)
            if not applied:
                return VerificationResult(
                    applied=False,
                    remaining_targets=target_keys or [],
                    message=f"Patch did not apply cleanly:\n{apply_out[-800:]}",
                )

            new_findings: list[Finding] = []
            for s in scanners:
                try:
                    new_findings.extend(s.scan(copy))
                except Exception:
                    continue
            new_findings = dedupe(new_findings)

            baseline_keys = {f.match_key() for f in baseline}
            new_keys = {f.match_key() for f in new_findings}
            resolved = sorted(baseline_keys - new_keys)
            introduced = [f for f in new_findings if f.match_key() not in baseline_keys]

            target_resolved: bool | None = None
            remaining: list[str] = []
            if target_keys:
                remaining = [k for k in target_keys if k in new_keys]
                target_resolved = len(remaining) == 0

            tests_passed: bool | None = None
            if test_command:
                tr = self.sandbox.run_capture(test_command, copy)
                tests_passed = tr.returncode == 0

            result = VerificationResult(
                applied=True,
                resolved=resolved,
                introduced=introduced,
                target_resolved=target_resolved,
                remaining_targets=remaining,
                tests_passed=tests_passed,
                regression_floor=Severity.coerce(config.REMEDIATION_REGRESSION_FLOOR),
            )
            result.message = self._describe(result)
            return result
        finally:
            shutil.rmtree(copy, ignore_errors=True)

    @staticmethod
    def _describe(r: VerificationResult) -> str:
        parts = []
        if r.verified:
            parts.append("✅ PATCH VERIFIED")
        else:
            parts.append("❌ PATCH NOT VERIFIED")
        parts.append(f"resolved {len(r.resolved)} finding(s)")
        if r.blocking_regressions:
            parts.append(f"⚠️ introduced {len(r.blocking_regressions)} regression(s) "
                         f"at/above {r.regression_floor.value}")
        if r.residual_regressions:
            parts.append(f"{len(r.residual_regressions)} lower-severity residual(s) (non-blocking)")
        if r.target_resolved is False:
            parts.append(f"target still present: {', '.join(r.remaining_targets)}")
        if r.tests_passed is not None:
            parts.append("tests passed" if r.tests_passed else "tests FAILED")
        return "; ".join(parts)


# ---------------------------------------------------------------------------
# Agent tool
# ---------------------------------------------------------------------------

def build_remediation_tools() -> list[Tool]:
    from .scanners.base import all_scanners, get_findings_store
    from .workspace import get_workspace

    def handler(diff: str, scanner: str = "", target_rule_id: str = "", test_command: str = "") -> str:
        if not diff or not diff.strip():
            return "Error: provide a unified diff to verify."
        baseline = dedupe(get_findings_store())
        if not baseline:
            return "No baseline findings. Run scan_all before verifying a patch."

        scanners = all_scanners()
        if scanner:
            scanners = [s for s in scanners if s.name == scanner] or scanners

        target_keys: list[str] = []
        if target_rule_id:
            target_keys = sorted({
                f.match_key() for f in baseline
                if f.rule_id == target_rule_id or f.cve == target_rule_id
            })

        result = RemediationVerifier().verify(
            workspace_dir=str(get_workspace()),
            diff=diff,
            scanners=scanners,
            baseline=baseline,
            target_keys=target_keys or None,
            test_command=test_command or None,
        )

        lines = [result.message]
        if result.resolved:
            lines.append("\nResolved: " + ", ".join(result.resolved[:20]))
        if result.blocking_regressions:
            lines.append("\nBlocking regressions (fix before shipping):")
            for f in result.blocking_regressions[:15]:
                loc = f"{f.file}:{f.line}" if f.file else "-"
                lines.append(f"- [{f.severity.value.upper()}] {loc} {f.rule_id} — {f.title}")
        if result.residual_regressions:
            lines.append("\nLower-severity residuals (non-blocking, worth noting):")
            for f in result.residual_regressions[:10]:
                loc = f"{f.file}:{f.line}" if f.file else "-"
                lines.append(f"- [{f.severity.value.upper()}] {loc} {f.rule_id} — {f.title}")
        if not result.applied:
            lines.append("\nFix the diff so it applies (check paths / context lines) and retry.")
        return "\n".join(lines)

    return [
        Tool(
            name="verify_patch",
            description=(
                "Verify a fix before trusting it. Applies a unified diff to an isolated "
                "copy of the workspace, re-runs the scanners, and reports whether the "
                "target finding is gone and whether any regressions were introduced. "
                "Optionally runs a test command. Never mutates the original workspace."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "diff": {"type": "string", "description": "Unified diff (git-style) of the fix."},
                    "scanner": {"type": "string", "description": "Restrict re-scan to one scanner (e.g. 'bandit'). Default: all."},
                    "target_rule_id": {"type": "string", "description": "Rule id or CVE the patch is meant to resolve."},
                    "test_command": {"type": "string", "description": "Optional command to run in the sandbox (0 exit = pass)."},
                },
                "required": ["diff"],
            },
            handler=handler,
        )
    ]
