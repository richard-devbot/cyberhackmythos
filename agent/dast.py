"""Live / dynamic testing (DAST) — gated and scoped to authorized hosts.

Unlike the code scanners, DAST reaches a LIVE target over the network, so it is
fenced by two controls that must BOTH pass:

1. ``CYBERHACKMYTHOS_DAST_ENABLED`` is true, and
2. the target host is on ``CYBERHACKMYTHOS_AUTHORIZED_TARGETS``.

Any target not on the allowlist is refused. This is the mechanism that keeps the
tool usable only against systems you own or are explicitly authorized to test.

The scan runs in the sandbox with network egress ENABLED (the one place we allow
it), using nuclei — a mainstream, template-driven web vulnerability scanner.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from . import config
from .findings import Category, Finding, Severity, dedupe, summarize
from .sandbox import Sandbox, get_sandbox
from .scanners.base import _format, get_findings_store
from .tools import Tool


# Session "arm" gate: even with DAST enabled + an allowlisted target, a live scan
# only fires after the operator explicitly arms it in the UI (confirming authorization).
_ARMED = {"on": False}


def set_armed(value: bool) -> None:
    _ARMED["on"] = bool(value)


def is_armed() -> bool:
    return _ARMED["on"]


def authorized_host(url: str) -> tuple[bool, str]:
    """Return (allowed, host). A host matches if it equals an allowlist entry, or
    an entry starts with '.' and the host ends with it (subdomain rule)."""
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False, ""
    for entry in config.AUTHORIZED_TARGETS:
        e = entry.strip().lower()
        if not e:
            continue
        if e.startswith("."):
            if host == e[1:] or host.endswith(e):
                return True, host
        elif host == e:
            return True, host
    return False, host


# ---------------------------------------------------------------------------
# nuclei — templated web/network vulnerability scanner
# ---------------------------------------------------------------------------

_NUCLEI_SEVERITY = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "low": Severity.LOW, "info": Severity.INFO, "unknown": Severity.UNKNOWN,
}


def parse_nuclei(stdout: str) -> list[Finding]:
    """Parse nuclei JSONL output (one JSON object per line) into findings."""
    findings: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = r.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        cwes = classification.get("cwe-id") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        cve_ids = classification.get("cve-id") or []
        cve = (cve_ids[0] if isinstance(cve_ids, list) and cve_ids else
               (cve_ids if isinstance(cve_ids, str) else None))
        findings.append(
            Finding(
                tool="nuclei",
                rule_id=r.get("template-id", "nuclei"),
                title=(info.get("name") or r.get("template-id", ""))[:140],
                severity=_NUCLEI_SEVERITY.get(str(info.get("severity", "")).lower(), Severity.UNKNOWN),
                category=Category.WEB,
                message=(info.get("description") or "")[:500],
                file=r.get("matched-at") or r.get("host"),
                cve=(cve.upper() if isinstance(cve, str) else None),
                cwe=[c.upper() for c in cwes if isinstance(c, str)],
            )
        )
    return findings


class DastRunner:
    def __init__(self, sandbox: Sandbox | None = None) -> None:
        self.sandbox = sandbox or get_sandbox()

    def scan(self, url: str) -> list[Finding]:
        # nuclei with JSONL output; network egress is required and enabled here.
        # Rate-limited + bounded concurrency to stay a good citizen against a live host.
        cmd = (
            f"HOME=/tmp nuclei -u {url} -jsonl -silent -no-color "
            f"-timeout 10 -retries 1 -rate-limit 40 -c 20 || true"
        )
        result = self.sandbox.run_capture(
            cmd, "/tmp", timeout=config.DAST_TIMEOUT_SECONDS, network=True
        )
        if result.returncode == 127 or "not found" in (result.stderr + result.stdout).lower():
            raise RuntimeError(
                "nuclei is not installed in the execution environment. Install it on the "
                "host (subprocess backend) or bake it into the DAST image (docker backend)."
            )
        return parse_nuclei(result.stdout)


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

def build_dast_tools() -> list[Tool]:
    """DAST tools — only call this when config.DAST_ENABLED is true."""

    def handler(url: str) -> str:
        if not config.DAST_ENABLED:
            return "DAST is disabled. Set CYBERHACKMYTHOS_DAST_ENABLED=true to enable live testing."
        if not is_armed():
            return ("Live testing is not armed. In the UI, toggle 'Live testing' on and confirm "
                    "you're authorized to test the configured targets before scanning.")
        if not url or not url.strip():
            return "Error: provide a target URL."
        allowed, host = authorized_host(url)
        if not allowed:
            allow = ", ".join(config.AUTHORIZED_TARGETS) or "(none configured)"
            return (
                f"Refused: '{host or url}' is not on the authorization allowlist.\n"
                f"Authorized targets: {allow}\n"
                f"Only test hosts you own or have written permission for. Add the host to "
                f"CYBERHACKMYTHOS_AUTHORIZED_TARGETS to authorize it."
            )
        try:
            findings = DastRunner().scan(url.strip())
        except Exception as exc:  # noqa: BLE001
            return f"DAST error: {exc}"
        findings = dedupe(findings)
        get_findings_store().extend(findings)
        header = f"### Live scan (nuclei) of {host} — AUTHORIZED"
        return _format(findings, header=header)

    return [
        Tool(
            name="dast_scan",
            description=(
                "Run a live dynamic scan (nuclei) against an AUTHORIZED target URL. "
                "Only works when DAST is enabled and the host is on the authorization "
                "allowlist — scans of unauthorized hosts are refused. Use for testing "
                "your own running applications for exposed vulnerabilities and misconfigs."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL, e.g. https://dev.example.com"}
                },
                "required": ["url"],
            },
            handler=handler,
        )
    ]


# Re-export for callers that want the histogram helper alongside DAST results.
__all__ = ["authorized_host", "parse_nuclei", "DastRunner", "build_dast_tools", "summarize"]
