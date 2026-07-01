"""Phase 3 tests: verified remediation.

Includes a real end-to-end proof: scan vulnerable code with bandit (baseline),
apply a genuine fix as a diff, and confirm verify_patch re-scans the isolated copy
and reports the finding resolved with no regressions.
"""

import os
import shutil

import pytest

from agent import config, sandbox
from agent.findings import Category, Finding, Severity
from agent.remediation import RemediationVerifier, VerificationResult, snapshot_workspace


# ---------------------------------------------------------------------------
# match_key is line-independent
# ---------------------------------------------------------------------------

def test_match_key_ignores_line():
    a = Finding("bandit", "B602", "x", Severity.HIGH, Category.SAST, file="a.py", line=4)
    b = Finding("bandit", "B602", "x", Severity.HIGH, Category.SAST, file="a.py", line=9)
    assert a.match_key() == b.match_key()  # same issue, shifted line


def test_match_key_dependency_by_cve():
    a = Finding("trivy", "CVE-1", "x", Severity.HIGH, Category.DEPENDENCY, package="Flask", cve="CVE-1")
    b = Finding("osv", "CVE-1", "x", Severity.LOW, Category.DEPENDENCY, package="flask", cve="cve-1")
    assert a.match_key() == b.match_key()


# ---------------------------------------------------------------------------
# VerificationResult.verified logic
# ---------------------------------------------------------------------------

def test_verified_true_when_target_resolved_no_regressions():
    r = VerificationResult(applied=True, resolved=["k1"], target_resolved=True)
    assert r.verified is True


def test_verified_false_on_blocking_regression():
    reg = Finding("bandit", "B602", "x", Severity.HIGH, Category.SAST, file="a.py", line=2)
    r = VerificationResult(applied=True, resolved=["k1"], introduced=[reg], target_resolved=True)
    assert r.blocking_regressions == [reg]
    assert r.verified is False


def test_low_severity_residual_is_non_blocking():
    residual = Finding("bandit", "B603", "x", Severity.LOW, Category.SAST, file="a.py", line=2)
    r = VerificationResult(applied=True, resolved=["k1"], introduced=[residual], target_resolved=True)
    assert r.blocking_regressions == []
    assert r.residual_regressions == [residual]
    assert r.verified is True  # trading a HIGH for a LOW is a net win


def test_verified_false_when_not_applied():
    assert VerificationResult(applied=False).verified is False


def test_verified_false_when_target_remains():
    r = VerificationResult(applied=True, resolved=[], target_resolved=False, remaining_targets=["k1"])
    assert r.verified is False


# ---------------------------------------------------------------------------
# Real end-to-end: bandit baseline -> apply fix -> re-scan -> resolved
# ---------------------------------------------------------------------------

def _bandit_available() -> bool:
    return shutil.which("bandit") is not None


@pytest.mark.skipif(not _bandit_available(), reason="bandit binary not installed")
def test_verify_patch_resolves_real_finding(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SANDBOX_BACKEND", "subprocess")
    from agent import workspace
    from agent.scanners.bandit import BanditScanner

    ws = workspace.set_workspace(tmp_path)
    vuln = "import subprocess\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n"
    workspace.write_file("vuln.py", vuln)

    sb = sandbox.Sandbox()
    scanner = BanditScanner(sandbox=sb)
    baseline = scanner.scan(str(ws))
    assert any(f.rule_id == "B602" for f in baseline), "expected shell=True finding in baseline"

    # A genuine fix: drop shell=True. (bandit still emits a LOW B603 residual for
    # subprocess use — that's expected and must NOT block verification.)
    diff = (
        "--- a/vuln.py\n"
        "+++ b/vuln.py\n"
        "@@ -1,4 +1,4 @@\n"
        " import subprocess\n"
        " \n"
        " def run(cmd):\n"
        "-    subprocess.call(cmd, shell=True)\n"
        "+    subprocess.call(cmd)\n"
    )

    result = RemediationVerifier(sandbox=sb).verify(
        workspace_dir=str(ws),
        diff=diff,
        scanners=[scanner],
        baseline=baseline,
        target_keys=[f.match_key() for f in baseline if f.rule_id == "B602"],
    )

    assert result.applied is True
    assert result.target_resolved is True
    assert result.verified is True
    # And the original workspace is untouched (still vulnerable).
    assert "shell=True" in (tmp_path / "vuln.py").read_text()


@pytest.mark.skipif(not _bandit_available(), reason="bandit binary not installed")
def test_verify_patch_rejects_bad_diff(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SANDBOX_BACKEND", "subprocess")
    from agent import workspace
    from agent.scanners.bandit import BanditScanner

    ws = workspace.set_workspace(tmp_path)
    workspace.write_file("vuln.py", "import subprocess\nsubprocess.call('x', shell=True)\n")
    sb = sandbox.Sandbox()
    scanner = BanditScanner(sandbox=sb)
    baseline = scanner.scan(str(ws))

    result = RemediationVerifier(sandbox=sb).verify(
        workspace_dir=str(ws),
        diff="--- a/nope.py\n+++ b/nope.py\n@@ -1 +1 @@\n-nonexistent\n+line\n",
        scanners=[scanner],
        baseline=baseline,
    )
    assert result.applied is False
    assert result.verified is False


def test_snapshot_is_isolated(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.txt").write_text("original")
    copy = snapshot_workspace(str(src))
    try:
        (src / "f.txt").write_text("modified original")
        # The snapshot retains the original content.
        assert (os.path.join(copy, "f.txt")) and open(os.path.join(copy, "f.txt")).read() == "original"
    finally:
        shutil.rmtree(copy, ignore_errors=True)
