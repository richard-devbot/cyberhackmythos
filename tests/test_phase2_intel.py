"""Phase 2 tests: threat-intel parsing, priority scoring, STRIDE, risk graph.

No network: HTTP responses are faked, and the pure logic (priority matrix, STRIDE
mapping, graph rendering) is tested directly.
"""

import pytest

from agent.findings import Category, Finding, Severity
from agent.graph import (
    ELEVATION,
    INFO_DISCLOSURE,
    TAMPERING,
    build_risk_graph,
    priority_table,
    stride_category,
    to_stride,
)
from agent.intel import (
    EPSSClient,
    KEVCatalog,
    NVDClient,
    ThreatIntel,
    score_priority,
    valid_cve,
)


# ---------------------------------------------------------------------------
# CVE validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cve,ok", [
    ("CVE-2021-44228", True),
    ("cve-2019-0001", True),
    ("CVE-20-1", False),
    ("not-a-cve", False),
    (None, False),
    ("CVE-2021-44228; rm -rf", False),  # no injection into URL
])
def test_valid_cve(cve, ok):
    assert valid_cve(cve) is ok


# ---------------------------------------------------------------------------
# Priority matrix (KEV overrides; EPSS/CVSS thresholds)
# ---------------------------------------------------------------------------

def test_priority_kev_overrides():
    p, reason = score_priority(kev=True, epss=0.0, cvss=1.0)
    assert p == "act_now" and "KEV" in reason


def test_priority_high_epss_acts_now():
    p, _ = score_priority(kev=False, epss=0.9, cvss=2.0)
    assert p == "act_now"


def test_priority_elevated_by_cvss_or_epss():
    assert score_priority(kev=False, epss=0.2, cvss=None)[0] == "attend"
    assert score_priority(kev=False, epss=None, cvss=8.5)[0] == "attend"


def test_priority_track_when_low():
    assert score_priority(kev=False, epss=0.01, cvss=3.0)[0] == "track"


# ---------------------------------------------------------------------------
# Client parsing with faked HTTP
# ---------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, payload):
        self._p = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


class _FakeSession:
    def __init__(self, payload):
        self._p = payload
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, params))
        return _FakeResp(self._p)


def test_epss_client_parses():
    payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97400", "percentile": "0.99999", "date": "2026-06-01"}]}
    client = EPSSClient(session=_FakeSession(payload))
    out = client.scores(["CVE-2021-44228"])
    assert out["CVE-2021-44228"]["epss"] == pytest.approx(0.974)
    assert out["CVE-2021-44228"]["percentile"] == pytest.approx(0.99999)


def test_kev_catalog_index_and_ransomware():
    feed = {"vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10",
         "knownRansomwareCampaignUse": "Known", "vulnerabilityName": "Log4Shell"},
        {"cveID": "CVE-2020-0001", "dateAdded": "2020-01-01",
         "knownRansomwareCampaignUse": "Unknown"},
    ]}
    kev = KEVCatalog()
    kev.load(feed)
    e = kev.lookup("cve-2021-44228")  # case-insensitive
    assert e is not None and e.ransomware is True
    assert kev.lookup("CVE-2020-0001").ransomware is False
    assert kev.lookup("CVE-2000-9999") is None


def test_nvd_parse_prefers_v31():
    data = {"vulnerabilities": [{"cve": {"metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                                        "vectorString": "CVSS:3.1/AV:N/..."}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}],
    }}}]}
    out = NVDClient.parse(data)
    assert out["score"] == 9.8 and out["version"] == "3.1" and out["severity"] == "CRITICAL"


def test_nvd_parse_empty():
    assert NVDClient.parse({"vulnerabilities": []}) is None


# ---------------------------------------------------------------------------
# End-to-end enrichment with injected clients (no network)
# ---------------------------------------------------------------------------

def test_enrich_findings_end_to_end():
    findings = [
        Finding("trivy", "CVE-2021-44228", "Log4Shell", Severity.CRITICAL,
                Category.DEPENDENCY, package="log4j", cve="CVE-2021-44228"),
        Finding("bandit", "B602", "shell", Severity.HIGH, Category.SAST, file="a.py", line=1),
    ]

    class _EPSS:
        def scores(self, cves):
            return {"CVE-2021-44228": {"epss": 0.97, "percentile": 0.99, "date": "2026-01-01"}}

    class _KEV:
        def lookup(self, cve):
            from agent.intel import KevEntry
            return KevEntry(cve="CVE-2021-44228", date_added="2021-12-10", ransomware=True)

    class _NVD:
        def cvss(self, cve):
            return {"score": 10.0, "severity": "CRITICAL", "vector": "", "version": "3.1"}

    ti = ThreatIntel(epss=_EPSS(), kev=_KEV(), nvd=_NVD())
    ti.enrich_findings(findings)

    dep = findings[0]
    assert dep.epss == 0.97 and dep.kev is True and dep.kev_ransomware is True
    assert dep.cvss_score == 10.0 and dep.priority == "act_now"
    # The non-CVE SAST finding is left untouched by CVE enrichment.
    assert findings[1].priority is None


# ---------------------------------------------------------------------------
# STRIDE mapping
# ---------------------------------------------------------------------------

def test_stride_by_cwe_and_category():
    sqli = Finding("semgrep", "r", "x", Severity.HIGH, Category.SAST, cwe=["CWE-89"])
    secret = Finding("gitleaks", "r", "x", Severity.HIGH, Category.SECRET, cwe=["CWE-798"])
    dep = Finding("trivy", "CVE-1", "x", Severity.HIGH, Category.DEPENDENCY, cve="CVE-1")
    assert stride_category(sqli) == TAMPERING
    assert stride_category(secret) == INFO_DISCLOSURE
    assert stride_category(dep) == ELEVATION  # category fallback

    buckets = to_stride([sqli, secret, dep])
    assert sqli in buckets[TAMPERING]
    assert secret in buckets[INFO_DISCLOSURE]


# ---------------------------------------------------------------------------
# Risk graph rendering
# ---------------------------------------------------------------------------

def test_risk_graph_mermaid():
    findings = [
        Finding("trivy", "CVE-1", "x", Severity.CRITICAL, Category.DEPENDENCY,
                package="log4j", cve="CVE-1", priority="act_now"),
    ]
    g = build_risk_graph(findings)
    assert g.startswith("flowchart LR")
    assert "log4j" in g and "CVE-1" in g
    assert "style" in g  # priority coloring applied


def test_risk_graph_empty():
    assert "No findings" in build_risk_graph([])


def test_priority_table_ranks_kev_first():
    low = Finding("t", "r1", "x", Severity.LOW, Category.SAST, file="a", line=1, priority="track")
    kev = Finding("t", "CVE-9", "y", Severity.CRITICAL, Category.DEPENDENCY,
                  cve="CVE-9", priority="act_now", kev=True)
    table = priority_table([low, kev])
    # The act_now/KEV row should appear before the track row.
    assert table.index("CVE-9") < table.index("r1")
