"""DAST tests: the authorization gate (the safety control) and nuclei parsing."""

import json

import pytest

from agent import config, dast
from agent.dast import authorized_host, parse_nuclei
from agent.findings import Category, Severity


# ---------------------------------------------------------------------------
# Authorization allowlist — the control that prevents scanning arbitrary hosts
# ---------------------------------------------------------------------------

def test_authorized_exact_host(monkeypatch):
    monkeypatch.setattr(config, "AUTHORIZED_TARGETS", ["dev.example.com"])
    assert authorized_host("https://dev.example.com/login")[0] is True
    assert authorized_host("https://other.com/")[0] is False


def test_authorized_subdomain_rule(monkeypatch):
    monkeypatch.setattr(config, "AUTHORIZED_TARGETS", [".example.com"])
    assert authorized_host("https://dev.example.com/")[0] is True
    assert authorized_host("https://api.staging.example.com/")[0] is True
    assert authorized_host("https://example.com/")[0] is True
    assert authorized_host("https://evil-example.com/")[0] is False  # not a real subdomain


def test_empty_allowlist_denies_everything(monkeypatch):
    monkeypatch.setattr(config, "AUTHORIZED_TARGETS", [])
    assert authorized_host("https://anything.com/")[0] is False


def test_dast_tool_refuses_unauthorized(monkeypatch):
    monkeypatch.setattr(config, "DAST_ENABLED", True)
    monkeypatch.setattr(config, "AUTHORIZED_TARGETS", ["dev.example.com"])
    tool = dast.build_dast_tools()[0]
    out = tool.handler(url="https://not-authorized.com/")
    assert "Refused" in out and "allowlist" in out


def test_dast_tool_disabled_message(monkeypatch):
    monkeypatch.setattr(config, "DAST_ENABLED", False)
    tool = dast.build_dast_tools()[0]
    assert "disabled" in tool.handler(url="https://dev.example.com/").lower()


# ---------------------------------------------------------------------------
# nuclei JSONL parsing
# ---------------------------------------------------------------------------

def test_parse_nuclei():
    lines = "\n".join(json.dumps(x) for x in [
        {"template-id": "CVE-2021-41773", "matched-at": "https://dev.example.com/cgi-bin",
         "host": "dev.example.com",
         "info": {"name": "Apache Path Traversal", "severity": "critical",
                  "description": "Path traversal in Apache 2.4.49",
                  "classification": {"cwe-id": ["CWE-22"], "cve-id": ["CVE-2021-41773"]}}},
        {"template-id": "tls-version", "matched-at": "dev.example.com:443",
         "info": {"name": "TLS 1.0 enabled", "severity": "low", "classification": {}}},
    ])
    fs = parse_nuclei(lines)
    assert len(fs) == 2
    crit = fs[0]
    assert crit.severity is Severity.CRITICAL and crit.category is Category.WEB
    assert crit.cve == "CVE-2021-41773" and crit.cwe == ["CWE-22"]
    assert crit.tool == "nuclei"
    assert fs[1].severity is Severity.LOW


def test_parse_nuclei_tolerates_noise():
    assert parse_nuclei("") == []
    assert parse_nuclei("starting nuclei...\nnot json\n") == []
