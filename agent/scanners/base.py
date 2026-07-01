"""Scanner base class, registry, and agent-tool adapters.

A :class:`Scanner` knows three things: the command that runs its tool, how to
parse that tool's native output into normalized :class:`Finding` objects, and its
category. Everything else — sandboxed execution, graceful handling of a missing
binary, formatting for the model, accumulating results for later SARIF export —
is shared here so each scanner stays a thin, well-tested adapter.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod

from ..findings import Category, Finding, dedupe, summarize
from ..sandbox import Sandbox, SandboxResult, get_sandbox
from ..tools import Tool
from ..workspace import resolve_in_workspace, write_file


class ScannerUnavailable(RuntimeError):
    """Raised when a scanner's binary is not present in the execution env."""


# -- shared parsing helpers -------------------------------------------------

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def norm_cwe(value: object) -> list[str]:
    """Normalize assorted CWE representations to ['CWE-89', ...]."""
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    out: list[str] = []
    for it in items:
        m = _CWE_RE.search(str(it))
        if m:
            out.append(f"CWE-{m.group(1)}")
    return sorted(set(out))


def as_str_list(value: object) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    return [str(v) for v in items]


def load_json(result: SandboxResult) -> object:
    """Parse a tool's stdout JSON, tolerating leading log noise."""
    text = (result.stdout or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Some tools prepend non-JSON lines; find the first JSON value.
        for opener in ("[", "{"):
            idx = text.find(opener)
            if idx != -1:
                try:
                    return json.loads(text[idx:])
                except json.JSONDecodeError:
                    continue
        return None


# Findings accumulate here across a run so a later export tool (Phase 4) can emit
# a full SARIF/HTML report. Bounded by clearing at the start of a fresh scan.
_FINDINGS_STORE: list[Finding] = []


def get_findings_store() -> list[Finding]:
    return _FINDINGS_STORE


def clear_findings_store() -> None:
    _FINDINGS_STORE.clear()


def _looks_like_missing_binary(result: SandboxResult, binary: str) -> bool:
    if result.returncode == 127:
        return True
    haystack = (result.stderr + result.stdout).lower()
    return f"{binary}: not found" in haystack or f"{binary}: command not found" in haystack


class Scanner(ABC):
    """Base class for a single security tool."""

    name: str = ""
    binary: str = ""
    category: Category = Category.MISC
    description: str = ""
    #: Some scanners return non-zero simply because they found issues. List the
    #: return codes that are "clean run, findings present" so we don't treat them
    #: as execution failures.
    ok_returncodes: tuple[int, ...] = (0,)

    def __init__(self, sandbox: Sandbox | None = None) -> None:
        self.sandbox = sandbox or get_sandbox()

    @abstractmethod
    def build_command(self, target: str = ".") -> str:
        """Shell command that runs the tool over *target* and prints JSON."""

    @abstractmethod
    def parse(self, result: SandboxResult) -> list[Finding]:
        """Turn the tool's native output into normalized findings."""

    # -- execution ---------------------------------------------------------
    def scan(self, workdir: str, target: str = ".") -> list[Finding]:
        result = self.sandbox.run_capture(self.build_command(target), workdir)
        if _looks_like_missing_binary(result, self.binary):
            raise ScannerUnavailable(
                f"'{self.binary}' is not available in the {result.isolation_level} "
                f"sandbox. Install it on the host (subprocess backend) or bake it "
                f"into the scanner image (docker backend)."
            )
        return self.parse(result)

    # -- agent tool adapter -----------------------------------------------
    def to_tool(self) -> Tool:
        def handler(target: str = ".") -> str:
            return run_and_format(self, target)

        return Tool(
            name=f"scan_{self.name}",
            description=(
                f"{self.description} Runs `{self.binary}` inside the sandbox over a "
                f"path in the analysis workspace (default: the whole workspace). "
                f"Returns normalized findings."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Path within the workspace to scan (default '.').",
                    }
                },
                "required": [],
            },
            handler=handler,
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def all_scanners(sandbox: Sandbox | None = None) -> list[Scanner]:
    """Instantiate every registered scanner."""
    from .semgrep import SemgrepScanner
    from .bandit import BanditScanner
    from .gitleaks import GitleaksScanner
    from .trivy import TrivyScanner
    from .hadolint import HadolintScanner

    classes = [
        SemgrepScanner,
        BanditScanner,
        GitleaksScanner,
        TrivyScanner,
        HadolintScanner,
    ]
    return [cls(sandbox=sandbox) for cls in classes]


# ---------------------------------------------------------------------------
# Formatting helpers (what the model actually reads back)
# ---------------------------------------------------------------------------

def _format(findings: list[Finding], header: str, max_rows: int = 40) -> str:
    if not findings:
        return f"{header}\nNo findings."
    counts = summarize(findings)
    hist = ", ".join(
        f"{k}={counts[k]}" for k in ("critical", "high", "medium", "low", "info") if counts[k]
    )
    lines = [f"{header}", f"Summary: {counts['total']} findings ({hist or 'none'})", ""]
    for f in findings[:max_rows]:
        loc = f"{f.file}:{f.line}" if f.file else "(no location)"
        tags = ""
        if f.cwe:
            tags += f" [{','.join(f.cwe)}]"
        if f.cve:
            tags += f" [{f.cve}]"
        lines.append(f"- [{f.severity.value.upper()}] {loc} — {f.title}{tags} ({f.tool})")
    if len(findings) > max_rows:
        lines.append(f"... and {len(findings) - max_rows} more")
    # Structured payload so the model can reason precisely.
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps([f.to_dict() for f in findings[:max_rows]], indent=2))
    lines.append("```")
    return "\n".join(lines)


def run_and_format(scanner: Scanner, target: str = ".") -> str:
    """Run one scanner and return a model-readable report; accumulate findings."""
    try:
        workdir = str(resolve_in_workspace(target))
    except ValueError as exc:
        return f"Error: {exc}"
    try:
        findings = scanner.scan(workdir, ".")
    except ScannerUnavailable as exc:
        return f"Scanner unavailable: {exc}"
    except Exception as exc:  # noqa: BLE001 - report any tool failure to the model
        return f"Error running {scanner.name}: {exc}"
    findings = dedupe(findings)
    _FINDINGS_STORE.extend(findings)
    return _format(findings, header=f"### {scanner.name} results ({scanner.category.value})")


def build_scanner_tools(sandbox: Sandbox | None = None) -> list[Tool]:
    """All scanner tools plus workspace + aggregate + export helpers."""
    scanners = all_scanners(sandbox=sandbox)
    tools = [s.to_tool() for s in scanners]
    tools.append(_write_file_tool())
    tools.append(_scan_all_tool(scanners))
    tools.append(_export_sarif_tool())
    return tools


def _write_file_tool() -> Tool:
    def handler(path: str, content: str) -> str:
        try:
            abs_path = write_file(path, content)
        except ValueError as exc:
            return f"Error: {exc}"
        return f"Wrote {len(content)} bytes to workspace: {path}\n(abs: {abs_path})"

    return Tool(
        name="write_file",
        description=(
            "Write code/content into the analysis workspace so scanners can run "
            "over it. Use this to stage a pasted codebase before scanning."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path within the workspace."},
                "content": {"type": "string", "description": "File contents."},
            },
            "required": ["path", "content"],
        },
        handler=handler,
    )


def _scan_all_tool(scanners: list[Scanner]) -> Tool:
    def handler(target: str = ".") -> str:
        try:
            workdir = str(resolve_in_workspace(target))
        except ValueError as exc:
            return f"Error: {exc}"
        all_findings: list[Finding] = []
        skipped: list[str] = []
        for s in scanners:
            try:
                all_findings.extend(s.scan(workdir, "."))
            except ScannerUnavailable:
                skipped.append(s.name)
            except Exception as exc:  # noqa: BLE001
                skipped.append(f"{s.name} (error: {exc})")
        merged = dedupe(all_findings)
        _FINDINGS_STORE.extend(merged)
        report = _format(merged, header="### Aggregate scan (all scanners, deduped)")
        if skipped:
            report += f"\n\n_Skipped/unavailable: {', '.join(skipped)}_"
        return report

    return Tool(
        name="scan_all",
        description=(
            "Run every available scanner (SAST, secrets, dependencies, IaC, "
            "container) over the workspace and return merged, deduplicated, "
            "severity-ranked findings. The best single entry point for an audit."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Path within the workspace (default '.')."}
            },
            "required": [],
        },
        handler=handler,
    )


def _export_sarif_tool() -> Tool:
    def handler() -> str:
        from ..findings import to_sarif

        findings = dedupe(_FINDINGS_STORE)
        sarif = to_sarif(findings)
        path = write_file("cyberhackmythos.sarif", sarif)
        return f"Wrote SARIF ({len(findings)} findings) to {path}"

    return Tool(
        name="export_sarif",
        description="Export all findings gathered so far as a SARIF 2.1.0 report into the workspace.",
        parameters={"type": "object", "properties": {}, "required": []},
        handler=handler,
    )
