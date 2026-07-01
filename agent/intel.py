"""Threat-intelligence enrichment for CVE findings.

Turns a raw CVE into a *prioritized* one by attaching three independent signals:

* **CVSS** (NVD) — how bad it is if exploited.
* **EPSS** (FIRST) — probability it will be exploited in the next 30 days (0..1).
* **CISA KEV** — whether it is *already* being exploited in the wild.

These are combined into a small, transparent priority label (act_now / attend /
track). This is a documented heuristic, not a proprietary score — every input and
threshold is visible and tunable via config.

Network note: these calls go OUT from the trusted app process to fixed public API
hosts. They never run inside the untrusted-code sandbox, so Phase 0's no-egress
guarantee for scanning is unaffected.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

import requests

from . import config
from .findings import Finding

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{3,}$", re.IGNORECASE)


def valid_cve(cve: str | None) -> bool:
    return bool(cve and _CVE_RE.match(cve.strip()))


# ---------------------------------------------------------------------------
# EPSS (FIRST) — exploitation probability
# ---------------------------------------------------------------------------

class EPSSClient:
    """Batch EPSS lookups. Public API, no key, 100 CVEs per request."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()

    def scores(self, cves: list[str]) -> dict[str, dict]:
        cves = [c.upper() for c in cves if valid_cve(c)]
        out: dict[str, dict] = {}
        for i in range(0, len(cves), 100):
            chunk = cves[i : i + 100]
            try:
                resp = self.session.get(
                    config.EPSS_API_URL,
                    params={"cve": ",".join(chunk)},
                    timeout=config.INTEL_TIMEOUT_SECONDS,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception:
                continue
            for row in data.get("data", []):
                cve = (row.get("cve") or "").upper()
                if not cve:
                    continue
                out[cve] = {
                    "epss": _to_float(row.get("epss")),
                    "percentile": _to_float(row.get("percentile")),
                    "date": row.get("date"),
                }
        return out


# ---------------------------------------------------------------------------
# CISA KEV — known-exploited catalog (download once, index by CVE)
# ---------------------------------------------------------------------------

@dataclass
class KevEntry:
    cve: str
    date_added: str | None
    ransomware: bool
    name: str | None = None


class KEVCatalog:
    """Caches the full KEV feed and answers per-CVE lookups."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self._index: dict[str, KevEntry] = {}
        self._fetched_at: float = 0.0

    def _fresh(self) -> bool:
        return self._index and (time.time() - self._fetched_at) < config.INTEL_CACHE_TTL_SECONDS

    def refresh(self, force: bool = False) -> None:
        if self._fresh() and not force:
            return
        try:
            resp = self.session.get(config.KEV_FEED_URL, timeout=config.INTEL_TIMEOUT_SECONDS)
            resp.raise_for_status()
            self.load(resp.json())
        except Exception:
            # Keep any stale index rather than dropping data on a transient error.
            return

    def load(self, feed: dict) -> None:
        index: dict[str, KevEntry] = {}
        for v in feed.get("vulnerabilities", []):
            cve = (v.get("cveID") or "").upper()
            if not cve:
                continue
            index[cve] = KevEntry(
                cve=cve,
                date_added=v.get("dateAdded"),
                ransomware=str(v.get("knownRansomwareCampaignUse", "")).strip().lower() == "known",
                name=v.get("vulnerabilityName"),
            )
        self._index = index
        self._fetched_at = time.time()

    def lookup(self, cve: str) -> KevEntry | None:
        self.refresh()
        return self._index.get((cve or "").upper())


# ---------------------------------------------------------------------------
# NVD — CVSS base score / severity / vector
# ---------------------------------------------------------------------------

class NVDClient:
    """Per-CVE CVSS lookup via NVD API 2.0. API key optional (raises rate limit)."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()

    def cvss(self, cve: str) -> dict | None:
        if not valid_cve(cve):
            return None
        headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
        try:
            resp = self.session.get(
                config.NVD_API_URL,
                params={"cveId": cve.upper()},
                headers=headers,
                timeout=config.INTEL_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return None
        return self.parse(data)

    @staticmethod
    def parse(data: dict) -> dict | None:
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return None
        metrics = (vulns[0].get("cve", {}) or {}).get("metrics", {}) or {}
        # Prefer CVSS v3.1, then v3.0, then v2.
        for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
            entries = metrics.get(key) or []
            if not entries:
                continue
            cvss_data = entries[0].get("cvssData", {}) or {}
            score = cvss_data.get("baseScore")
            if score is None:
                continue
            severity = (
                cvss_data.get("baseSeverity")
                or entries[0].get("baseSeverity")  # v2 puts it on the entry
            )
            return {
                "score": _to_float(score),
                "severity": severity,
                "vector": cvss_data.get("vectorString"),
                "version": ver,
            }
        return None


# ---------------------------------------------------------------------------
# Priority scoring (transparent heuristic)
# ---------------------------------------------------------------------------

def score_priority(
    *,
    kev: bool,
    epss: float | None,
    cvss: float | None,
) -> tuple[str, str]:
    """Return (priority, human reason).

    KEV overrides everything (it is *already* being exploited). Otherwise EPSS
    (likelihood) and CVSS (impact) decide. Thresholds are configurable.
    """
    if kev:
        return "act_now", "On CISA KEV — actively exploited in the wild."
    reasons: list[str] = []
    if epss is not None and epss >= config.EPSS_ACT_NOW:
        return "act_now", f"EPSS {epss:.0%} ≥ {config.EPSS_ACT_NOW:.0%} exploitation probability."
    if (epss is not None and epss >= config.EPSS_ATTEND) or (cvss is not None and cvss >= config.CVSS_ATTEND):
        if epss is not None and epss >= config.EPSS_ATTEND:
            reasons.append(f"EPSS {epss:.0%}")
        if cvss is not None and cvss >= config.CVSS_ATTEND:
            reasons.append(f"CVSS {cvss:.1f}")
        return "attend", "Elevated: " + ", ".join(reasons) + "."
    return "track", "Low likelihood and impact by current signals."


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class ThreatIntel:
    """Enriches findings that carry a CVE with EPSS + KEV + CVSS + priority."""

    def __init__(
        self,
        epss: EPSSClient | None = None,
        kev: KEVCatalog | None = None,
        nvd: NVDClient | None = None,
    ) -> None:
        session = requests.Session()
        self.epss = epss or EPSSClient(session)
        self.kev = kev or KEVCatalog(session)
        self.nvd = nvd or NVDClient(session)

    def enrich_findings(self, findings: list[Finding]) -> list[Finding]:
        cves = sorted({f.cve.upper() for f in findings if valid_cve(f.cve)})
        if not cves:
            return findings
        epss_map = self.epss.scores(cves)
        for f in findings:
            if not valid_cve(f.cve):
                continue
            cve = f.cve.upper()
            row = epss_map.get(cve)
            if row:
                f.epss = row.get("epss")
                f.epss_percentile = row.get("percentile")
            kev_entry = self.kev.lookup(cve)
            if kev_entry:
                f.kev = True
                f.kev_ransomware = kev_entry.ransomware
            # Fill CVSS from NVD only when the scanner didn't already supply one.
            if f.cvss_score is None and config.NVD_ENABLED:
                cvss = self.nvd.cvss(cve)
                if cvss:
                    f.cvss_score = cvss.get("score")
            f.priority, _reason = score_priority(kev=f.kev, epss=f.epss, cvss=f.cvss_score)
        return findings


def _to_float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
