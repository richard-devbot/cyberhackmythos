"""UI dashboard renderer tests (pure HTML functions, no browser)."""

from agent.dashboard import render_dashboard
from agent.findings import Category, Finding, Severity


def _sample() -> list[Finding]:
    return [
        Finding("trivy", "CVE-2021-44228", "Log4Shell RCE", Severity.CRITICAL, Category.DEPENDENCY,
                package="log4j-core", cve="CVE-2021-44228", cvss_score=10.0, epss=0.99999,
                kev=True, priority="act_now"),
        Finding("bandit", "B602", "shell=True", Severity.HIGH, Category.SAST,
                file="a.py", line=3, cwe=["CWE-78"], priority="attend"),
        Finding("hadolint", "DL3008", "pin apt", Severity.LOW, Category.CONTAINER,
                file="Dockerfile", line=5, priority="track"),
    ]


def test_empty_dashboard_renders():
    html = render_dashboard([])
    assert "cm-root" in html
    assert "awaiting scan" in html
    assert "No findings yet" in html  # empty findings table state


def test_dashboard_contains_findings_and_encoding():
    html = render_dashboard(_sample())
    # KPI + charts present
    assert "conic-gradient" in html          # severity donut
    assert "STRIDE" in html
    assert "Risk hotspots" in html
    # Severity encoded by shape + label (accessible, not color-only)
    assert "CRITICAL" in html and "■" in html
    assert "HIGH" in html and "▲" in html
    # Priority + KEV + intel columns
    assert "ACT NOW" in html
    assert "KEV" in html
    assert "10.0" in html          # CVSS
    assert "log4j-core" in html    # risk hotspot / package


def test_dashboard_escapes_untrusted_text():
    # A malicious finding title must not inject markup into the dashboard.
    evil = Finding("semgrep", "r", "<script>alert(1)</script>", Severity.HIGH,
                   Category.SAST, file="x.py", line=1)
    html = render_dashboard([evil])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_severity_stripe_uses_finding_color():
    html = render_dashboard(_sample())
    # Each row carries a severity-colored stripe via the --sev custom property.
    assert "--sev:#ff5964" in html  # critical color on the Log4Shell row
