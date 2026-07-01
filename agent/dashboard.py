"""Findings dashboard renderer.

Pure functions that turn the normalized ``Finding`` set into a self-contained
HTML dashboard (inline ``<style>`` so it renders identically inside Gradio and in
a standalone preview). No JavaScript is required.

Design: a "night operations console". Severity is encoded by shape + label +
color + a row stripe (never color alone, for accessibility). Monospace carries
labels and data (the vernacular of security tooling); a single cold cyan accent
is used sparingly and kept distinct from the semantic severity palette. Charts
are CSS ``conic-gradient`` / bars — no external libraries, no fonts over the wire.
"""

from __future__ import annotations

import html

from .findings import Category, Finding, Severity, summarize
from .graph import STRIDE_ORDER, to_stride

# Severity visual system: distinct SHAPE + label + color (accessible, not color-only).
_SEV_META: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("■", "#ff5964"),
    Severity.HIGH: ("▲", "#ff8c42"),
    Severity.MEDIUM: ("◆", "#f5c542"),
    Severity.LOW: ("●", "#4d9fff"),
    Severity.INFO: ("·", "#697082"),
    Severity.UNKNOWN: ("·", "#697082"),
}

_PRIORITY_META = {
    "act_now": ("ACT NOW", "#ff5964"),
    "attend": ("ATTEND", "#ff8c42"),
    "track": ("TRACK", "#38d9c4"),
}

# Compact monospace category tags (vernacular of the tooling, not emoji).
_CATEGORY_TAG = {
    Category.SAST: "SAST",
    Category.SECRET: "SEC",
    Category.DEPENDENCY: "DEP",
    Category.IAC: "IAC",
    Category.CONTAINER: "IMG",
    Category.MISC: "—",
}


def _esc(s: object) -> str:
    return html.escape(str(s if s is not None else ""))


def _sev_chip(sev: Severity) -> str:
    icon, color = _SEV_META[sev]
    return (
        f'<span class="cm-sev" style="--sev:{color}">'
        f'<span class="cm-sev-ico" aria-hidden="true">{icon}</span>'
        f'<span class="cm-sev-lbl">{sev.value.upper()}</span></span>'
    )


def _priority_chip(priority: str | None) -> str:
    if not priority or priority not in _PRIORITY_META:
        return '<span class="cm-pri cm-pri-none">—</span>'
    label, color = _PRIORITY_META[priority]
    return f'<span class="cm-pri" style="--pri:{color}">{label}</span>'


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _kpi_cards(findings: list[Finding]) -> str:
    c = summarize(findings)
    act_now = sum(1 for f in findings if f.priority == "act_now")
    kev = sum(1 for f in findings if f.kev)
    cards = [
        ("findings", c["total"], "var(--txt)"),
        ("critical", c["critical"], "#ff5964"),
        ("high", c["high"], "#ff8c42"),
        ("act now", act_now, "#ff5964"),
        ("on cisa kev", kev, "#ff5964"),
    ]
    inner = "".join(
        f'<div class="cm-kpi"><div class="cm-kpi-n" style="color:{col}">{val}</div>'
        f'<div class="cm-kpi-l">{_esc(label)}</div></div>'
        for label, val, col in cards
    )
    return f'<div class="cm-kpis">{inner}</div>'


def _severity_donut(findings: list[Finding]) -> str:
    c = summarize(findings)
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    total = sum(c[s.value] for s in order) or 1
    stops: list[str] = []
    acc = 0.0
    legend: list[str] = []
    for s in order:
        n = c[s.value]
        if n == 0:
            continue
        icon, color = _SEV_META[s]
        start = acc / total * 360
        acc += n
        end = acc / total * 360
        stops.append(f"{color} {start:.2f}deg {end:.2f}deg")
        legend.append(
            f'<li><span class="cm-dot" style="color:{color}">{icon}</span>'
            f'<span class="cm-leg-l">{s.value}</span><b>{n}</b></li>'
        )
    gradient = ", ".join(stops) if stops else "#222937 0deg 360deg"
    return (
        '<div class="cm-donut-wrap">'
        f'<div class="cm-donut" style="background:conic-gradient({gradient})">'
        f'<div class="cm-donut-hole"><span>{c["total"]}</span><small>total</small></div></div>'
        f'<ul class="cm-legend">{"".join(legend) or "<li>No findings</li>"}</ul>'
        '</div>'
    )


def _stride_panel(findings: list[Finding]) -> str:
    buckets = to_stride(findings)
    maxn = max((len(v) for v in buckets.values()), default=0) or 1
    rows = []
    for cat in STRIDE_ORDER:
        n = len(buckets[cat])
        pct = int(n / maxn * 100) if n else 0
        dim = "" if n else " cm-dim"
        rows.append(
            f'<div class="cm-stride-row{dim}"><span class="cm-stride-lbl">{_esc(cat)}</span>'
            f'<span class="cm-stride-bar"><span style="width:{pct}%"></span></span>'
            f'<span class="cm-stride-n">{n}</span></div>'
        )
    return f'<section class="cm-panel"><h3>STRIDE</h3>{"".join(rows)}</section>'


def _risk_list(findings: list[Finding], limit: int = 7) -> str:
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.package or f.file or "(unknown)", []).append(f)

    top = sorted(
        groups.items(),
        key=lambda kv: max((x.severity.rank for x in kv[1]), default=0),
        reverse=True,
    )[:limit]
    rows = []
    for name, items in top:
        worst = max(items, key=lambda x: x.severity.rank)
        _, color = _SEV_META[worst.severity]
        rows.append(
            f'<div class="cm-risk-row"><span class="cm-risk-bar" style="background:{color}"></span>'
            f'<span class="cm-risk-name">{_esc(name)}</span>'
            f'<span class="cm-risk-count">{len(items)}</span></div>'
        )
    body = "".join(rows) or '<div class="cm-empty">No hotspots.</div>'
    return f'<section class="cm-panel"><h3>Risk hotspots</h3>{body}</section>'


def _findings_table(findings: list[Finding]) -> str:
    if not findings:
        return (
            '<section class="cm-panel"><h3>Findings</h3>'
            '<div class="cm-empty">No findings yet — run a scan to populate the dashboard.</div></section>'
        )
    ranked = sorted(
        findings,
        key=lambda f: ({"act_now": 3, "attend": 2, "track": 1}.get(f.priority or "", 0),
                       f.severity.rank, f.epss or 0.0),
        reverse=True,
    )
    rows = []
    for f in ranked:
        _, sev_color = _SEV_META[f.severity]
        loc = f"{_esc(f.file)}:{f.line}" if f.file else "—"
        epss = f"{f.epss:.0%}" if f.epss is not None else "—"
        cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—"
        kev = '<span class="cm-kev" title="On CISA KEV — actively exploited">KEV</span>' if f.kev else ""
        tags = " ".join(_esc(x) for x in (f.cwe[:2] + ([f.cve] if f.cve else [])))
        cat = _CATEGORY_TAG.get(f.category, "—")
        rows.append(
            f'<tr style="--sev:{sev_color}">'
            f'<td class="cm-stripe">{_priority_chip(f.priority)}</td>'
            f"<td>{_sev_chip(f.severity)}</td>"
            f'<td class="cm-num">{cvss}</td>'
            f'<td class="cm-num">{epss}</td>'
            f"<td>{kev}</td>"
            f'<td><span class="cm-cat">{cat}</span></td>'
            f'<td class="cm-find">{_esc(f.title)}<span class="cm-tags">{tags}</span></td>'
            f'<td class="cm-loc">{loc}</td>'
            f'<td class="cm-tool">{_esc(f.tool)}</td>'
            "</tr>"
        )
    return (
        '<section class="cm-panel cm-tablewrap"><h3>Findings</h3>'
        '<table class="cm-table"><thead><tr>'
        "<th>Priority</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>KEV</th>"
        "<th>Cat</th><th>Finding</th><th>Location</th><th>Tool</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></section>"
    )


def dashboard_styles() -> str:
    return """
<style>
.cm-root{
  --bg:#0a0d14;--panel:#111725;--panel2:#161d2c;--edge:#212a3d;--edge2:#2b3550;
  --txt:#e8ecf4;--muted:#7f8aa3;--accent:#38d9c4;
  --mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,'Cascadia Mono',monospace;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:radial-gradient(1200px 500px at 15% -10%,#12203a 0%,var(--bg) 55%);
  color:var(--txt);padding:24px;border-radius:10px;font-family:var(--sans)}
.cm-head{display:flex;align-items:baseline;justify-content:space-between;gap:14px;flex-wrap:wrap;
  padding-bottom:16px;margin-bottom:18px;border-bottom:1px solid var(--edge)}
.cm-title{font-size:15px;font-weight:600;letter-spacing:.2px;display:flex;align-items:center;gap:11px;
  font-family:var(--mono);text-transform:lowercase}
.cm-mark{width:11px;height:11px;background:var(--accent);transform:rotate(45deg);
  box-shadow:0 0 12px rgba(56,217,196,.6);flex:0 0 auto}
.cm-sub{color:var(--muted);font-size:11px;font-family:var(--mono);letter-spacing:.4px}
.cm-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:16px}
.cm-kpi{background:var(--panel);border:1px solid var(--edge);border-radius:8px;padding:14px 16px;
  position:relative;overflow:hidden}
.cm-kpi::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent);opacity:.5}
.cm-kpi-n{font-size:28px;font-weight:700;font-variant-numeric:tabular-nums;line-height:1;font-family:var(--mono)}
.cm-kpi-l{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-top:7px;font-family:var(--mono)}
.cm-grid{display:grid;grid-template-columns:1.15fr 1fr 1fr;gap:12px;margin-bottom:12px}
@media(max-width:820px){.cm-grid{grid-template-columns:1fr}}
.cm-panel{background:var(--panel);border:1px solid var(--edge);border-radius:8px;padding:16px 18px}
.cm-panel h3{margin:0 0 14px;font-size:10px;text-transform:uppercase;letter-spacing:1.4px;
  color:var(--muted);font-family:var(--mono);font-weight:600}
.cm-donut-wrap{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.cm-donut{width:118px;height:118px;border-radius:50%;display:grid;place-items:center;flex:0 0 auto}
.cm-donut-hole{width:78px;height:78px;background:var(--panel);border-radius:50%;display:grid;place-items:center;text-align:center}
.cm-donut-hole span{font-size:24px;font-weight:700;font-family:var(--mono);font-variant-numeric:tabular-nums}
.cm-donut-hole small{display:block;color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:1px}
.cm-legend{list-style:none;margin:0;padding:0;font-size:12px;font-family:var(--mono);flex:1;min-width:120px}
.cm-legend li{display:flex;align-items:center;gap:9px;padding:3px 0}
.cm-dot{font-size:11px;width:12px;text-align:center}
.cm-leg-l{flex:1;color:var(--muted);text-transform:capitalize}
.cm-legend b{font-variant-numeric:tabular-nums}
.cm-sev{display:inline-flex;align-items:center;gap:7px;font-weight:600;font-size:11px;color:var(--sev);font-family:var(--mono)}
.cm-sev-ico{font-size:10px}
.cm-pri{font-size:9px;font-weight:700;letter-spacing:.8px;padding:3px 8px;border-radius:3px;
  color:#07090e;background:var(--pri);font-family:var(--mono);white-space:nowrap}
.cm-pri-none{color:var(--muted);background:transparent;padding-left:0}
.cm-stride-row{display:grid;grid-template-columns:132px 1fr 24px;align-items:center;gap:10px;margin:8px 0;
  font-size:12px;font-family:var(--mono)}
.cm-stride-row.cm-dim{opacity:.4}
.cm-stride-lbl{color:var(--muted);font-size:11px}
.cm-stride-bar{height:6px;background:var(--panel2);border-radius:4px;overflow:hidden}
.cm-stride-bar>span{display:block;height:100%;background:linear-gradient(90deg,var(--accent),#5b8def)}
.cm-stride-n{text-align:right;color:var(--txt);font-variant-numeric:tabular-nums}
.cm-risk-row{display:flex;align-items:center;gap:11px;padding:7px 0;font-size:12px;font-family:var(--mono)}
.cm-risk-bar{width:3px;height:20px;border-radius:2px;flex:0 0 auto}
.cm-risk-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#aeb9d4}
.cm-risk-count{color:var(--muted);font-variant-numeric:tabular-nums}
.cm-tablewrap{overflow-x:auto}
.cm-table{width:100%;border-collapse:collapse;font-size:13px;min-width:780px}
.cm-table th{text-align:left;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:1px;
  padding:9px 12px;border-bottom:1px solid var(--edge2);font-family:var(--mono);font-weight:600}
.cm-table td{padding:11px 12px;border-bottom:1px solid var(--edge);vertical-align:middle}
.cm-table tbody tr{transition:background .12s ease}
.cm-table tbody tr:hover td{background:var(--panel2)}
.cm-stripe{border-left:3px solid var(--sev)}
.cm-num{font-variant-numeric:tabular-nums;font-family:var(--mono);color:#c7cfe0}
.cm-cat{font-family:var(--mono);font-size:10px;letter-spacing:.5px;color:var(--muted);
  border:1px solid var(--edge2);border-radius:3px;padding:2px 6px}
.cm-find{max-width:340px}
.cm-tags{display:block;color:var(--muted);font-size:10px;font-family:var(--mono);margin-top:3px}
.cm-loc{font-family:var(--mono);font-size:11px;color:#8fa6cf}
.cm-tool{color:var(--muted);font-size:11px;font-family:var(--mono)}
.cm-kev{background:#ff5964;color:#07090e;font-size:9px;font-weight:800;padding:2px 6px;border-radius:3px;font-family:var(--mono)}
.cm-empty{color:var(--muted);padding:16px;text-align:center;font-size:12px;font-family:var(--mono)}
@media(prefers-reduced-motion:reduce){.cm-table tbody tr{transition:none}}
</style>
"""


def render_dashboard(findings: list[Finding], *, embed_styles: bool = True) -> str:
    """Full dashboard HTML for the given findings."""
    styles = dashboard_styles() if embed_styles else ""
    c = summarize(findings)
    subtitle = (
        f"{c['total']} findings · {c['critical']} critical · {c['high']} high"
        if findings else "awaiting scan"
    )
    return (
        f'{styles}<div class="cm-root">'
        '<header class="cm-head">'
        '<div class="cm-title"><span class="cm-mark"></span>cyberhackmythos · security console</div>'
        f'<div class="cm-sub">{_esc(subtitle)}</div></header>'
        f'{_kpi_cards(findings)}'
        '<div class="cm-grid">'
        f'<section class="cm-panel"><h3>Severity distribution</h3>{_severity_donut(findings)}</section>'
        f'{_stride_panel(findings)}'
        f'{_risk_list(findings)}'
        '</div>'
        f'{_findings_table(findings)}'
        '</div>'
    )
