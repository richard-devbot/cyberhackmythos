"""Phase 1 tests: scanner parsers, the Finding model, dedup, SARIF, workspace.

Parsers are tested against real sample output from each tool, so a schema drift
or a regression in normalization is caught without needing the binaries present.
"""

import json

import pytest

from agent.findings import Category, Finding, Severity, dedupe, summarize, to_sarif
from agent.sandbox import SandboxResult
from agent.scanners.base import ScannerUnavailable
from agent.scanners.semgrep import SemgrepScanner
from agent.scanners.bandit import BanditScanner
from agent.scanners.gitleaks import GitleaksScanner
from agent.scanners.trivy import TrivyScanner
from agent.scanners.hadolint import HadolintScanner


class FakeSandbox:
    """Stand-in sandbox returning a fixed result (no real execution)."""

    def __init__(self, stdout="", stderr="", returncode=0):
        self._r = SandboxResult(
            stdout=stdout, stderr=stderr, returncode=returncode,
            timed_out=False, isolation_level="test", network_enforced=True,
        )

    def run_capture(self, command, workdir, timeout=None, network=None):
        return self._r


def _result(stdout):
    return SandboxResult(stdout=stdout, stderr="", returncode=0, timed_out=False,
                         isolation_level="test", network_enforced=True)


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("ERROR", Severity.HIGH),
    ("error", Severity.HIGH),
    ("CRITICAL", Severity.CRITICAL),
    ("warning", Severity.MEDIUM),
    ("moderate", Severity.MEDIUM),
    ("LOW", Severity.LOW),
    ("note", Severity.INFO),
    (None, Severity.UNKNOWN),
    ("banana", Severity.UNKNOWN),
])
def test_severity_coerce(raw, expected):
    assert Severity.coerce(raw) is expected


def test_dedupe_collapses_same_cve_across_tools():
    a = Finding("trivy", "CVE-1", "x", Severity.HIGH, Category.DEPENDENCY, package="flask", cwe=["CWE-400"])
    b = Finding("osv", "CVE-1", "x", Severity.CRITICAL, Category.DEPENDENCY, package="flask", cwe=["CWE-79"])
    out = dedupe([a, b])
    assert len(out) == 1
    assert out[0].severity is Severity.CRITICAL          # higher severity wins
    assert out[0].cwe == ["CWE-400", "CWE-79"]           # tags merged
    assert "osv" in out[0].tool and "trivy" in out[0].tool


def test_dedupe_keeps_distinct_findings():
    a = Finding("semgrep", "r1", "x", Severity.HIGH, Category.SAST, file="a.py", line=1)
    b = Finding("semgrep", "r2", "y", Severity.LOW, Category.SAST, file="a.py", line=2)
    assert len(dedupe([a, b])) == 2


def test_summarize_histogram():
    fs = [Finding("t", "r", "x", Severity.HIGH, Category.SAST),
          Finding("t", "r2", "y", Severity.HIGH, Category.SAST, file="b", line=1)]
    s = summarize(fs)
    assert s["high"] == 2 and s["total"] == 2


def test_sarif_is_valid_and_complete():
    fs = [Finding("semgrep", "rule.x", "SQLi", Severity.CRITICAL, Category.SAST,
                  message="msg", file="app.py", line=10, cwe=["CWE-89"])]
    doc = json.loads(to_sarif(fs))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "cyberhackmythos"
    assert run["results"][0]["ruleId"] == "rule.x"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 10


# ---------------------------------------------------------------------------
# Scanner parsers (real sample output)
# ---------------------------------------------------------------------------

def test_semgrep_parse():
    out = json.dumps({"results": [{
        "check_id": "python.lang.security.dangerous-subprocess-use",
        "path": "app.py",
        "start": {"line": 42, "col": 5},
        "extra": {
            "message": "Detected subprocess with user input.",
            "severity": "ERROR",
            "metadata": {"cwe": ["CWE-78: OS Command Injection"], "owasp": ["A03:2021 - Injection"]},
        },
    }], "errors": []})
    fs = SemgrepScanner(sandbox=FakeSandbox()).parse(_result(out))
    assert len(fs) == 1
    f = fs[0]
    assert f.severity is Severity.HIGH and f.cwe == ["CWE-78"]
    assert f.file == "app.py" and f.line == 42 and f.category is Category.SAST
    assert f.owasp == ["A03:2021 - Injection"]


def test_bandit_parse():
    out = json.dumps({"results": [{
        "filename": "app.py", "issue_severity": "MEDIUM", "issue_confidence": "HIGH",
        "issue_text": "subprocess call with shell=True identified.",
        "line_number": 10, "test_id": "B602",
        "test_name": "subprocess_popen_with_shell_equals_true",
        "issue_cwe": {"id": 78, "link": "..."},
    }]})
    fs = BanditScanner(sandbox=FakeSandbox()).parse(_result(out))
    assert len(fs) == 1
    assert fs[0].rule_id == "B602" and fs[0].severity is Severity.MEDIUM
    assert fs[0].cwe == ["CWE-78"] and fs[0].line == 10


def test_gitleaks_parse_hides_secret():
    out = json.dumps([{
        "Description": "AWS Access Key", "StartLine": 3, "EndLine": 3,
        "File": "config.py", "RuleID": "aws-access-token",
        "Secret": "AKIAIOSFODNN7EXAMPLE", "Match": "AKIAIOSFODNN7EXAMPLE",
    }])
    fs = GitleaksScanner(sandbox=FakeSandbox()).parse(_result(out))
    assert len(fs) == 1
    f = fs[0]
    assert f.severity is Severity.HIGH and f.category is Category.SECRET
    assert f.cwe == ["CWE-798"] and f.file == "config.py" and f.line == 3
    # The secret value must never appear in the finding we surface.
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(f.to_dict())


def test_trivy_parse_vulns_misconfig_secrets():
    out = json.dumps({"Results": [
        {"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip",
         "Vulnerabilities": [{
             "VulnerabilityID": "CVE-2019-1010083", "PkgName": "flask",
             "InstalledVersion": "0.12.2", "FixedVersion": "1.0",
             "Severity": "HIGH", "Title": "Flask DoS", "CweIDs": ["CWE-400"]}]},
        {"Target": "Dockerfile", "Class": "config",
         "Misconfigurations": [{"ID": "DS002", "Title": "root user",
             "Severity": "HIGH", "Message": "Specify USER",
             "CauseMetadata": {"StartLine": 1}}],
         "Secrets": [{"RuleID": "github-pat", "Title": "GitHub PAT",
             "Severity": "CRITICAL", "StartLine": 5}]},
    ]})
    fs = TrivyScanner(sandbox=FakeSandbox()).parse(_result(out))
    cats = {f.category for f in fs}
    assert cats == {Category.DEPENDENCY, Category.IAC, Category.SECRET}
    dep = next(f for f in fs if f.category is Category.DEPENDENCY)
    assert dep.cve == "CVE-2019-1010083" and dep.package == "flask"
    assert dep.fixed_version == "1.0" and dep.cwe == ["CWE-400"]
    sec = next(f for f in fs if f.category is Category.SECRET)
    assert sec.severity is Severity.CRITICAL and sec.line == 5


def test_hadolint_parse():
    out = json.dumps([{"line": 3, "code": "DL3008",
                       "message": "Pin versions in apt get install",
                       "column": 1, "file": "Dockerfile", "level": "warning"}])
    fs = HadolintScanner(sandbox=FakeSandbox()).parse(_result(out))
    assert len(fs) == 1
    assert fs[0].rule_id == "DL3008" and fs[0].severity is Severity.MEDIUM
    assert fs[0].category is Category.CONTAINER and fs[0].line == 3


def test_parsers_tolerate_empty_or_garbage():
    for scanner in (SemgrepScanner, BanditScanner, GitleaksScanner, TrivyScanner, HadolintScanner):
        s = scanner(sandbox=FakeSandbox())
        assert s.parse(_result("")) == []
        assert s.parse(_result("not json at all")) == []


# ---------------------------------------------------------------------------
# Missing-binary handling
# ---------------------------------------------------------------------------

def test_scan_raises_when_binary_missing():
    scanner = SemgrepScanner(sandbox=FakeSandbox(stderr="semgrep: not found", returncode=127))
    with pytest.raises(ScannerUnavailable):
        scanner.scan("/tmp")


# ---------------------------------------------------------------------------
# Workspace path-traversal guard
# ---------------------------------------------------------------------------

def test_workspace_blocks_traversal(tmp_path):
    from agent import workspace
    workspace.set_workspace(tmp_path)
    with pytest.raises(ValueError):
        workspace.resolve_in_workspace("../../etc/passwd")
    # A normal relative path resolves inside the workspace.
    p = workspace.write_file("sub/app.py", "print('hi')")
    assert str(tmp_path) in p
