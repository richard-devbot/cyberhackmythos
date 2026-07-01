import type { Category, Finding, Priority, Severity } from "./types";

// Severity is encoded by SHAPE + label + color (never color alone) for accessibility.
export const SEV_META: Record<
  Severity,
  { label: string; color: string; shape: string; rank: number }
> = {
  critical: { label: "Critical", color: "#ff4d5e", shape: "■", rank: 5 },
  high: { label: "High", color: "#ff8a3d", shape: "▲", rank: 4 },
  medium: { label: "Medium", color: "#f5c451", shape: "◆", rank: 3 },
  low: { label: "Low", color: "#4d9fff", shape: "●", rank: 2 },
  info: { label: "Info", color: "#6b7488", shape: "·", rank: 1 },
  unknown: { label: "Unknown", color: "#6b7488", shape: "·", rank: 0 },
};

export const PRIORITY_META: Record<Priority, { label: string; color: string; blurb: string }> = {
  act_now: { label: "Act now", color: "#ff4d5e", blurb: "Exploited or highly likely" },
  attend: { label: "Attend", color: "#ff8a3d", blurb: "Elevated risk" },
  track: { label: "Track", color: "#35e0d0", blurb: "Monitor" },
};

export const CATEGORY_META: Record<Category, { tag: string; label: string }> = {
  sast: { tag: "SAST", label: "Static analysis" },
  secret: { tag: "SEC", label: "Secret" },
  dependency: { tag: "DEP", label: "Dependency" },
  iac: { tag: "IAC", label: "Infrastructure" },
  container: { tag: "IMG", label: "Container" },
  misc: { tag: "—", label: "Other" },
};

export function priorityRank(p?: Priority | null): number {
  return p === "act_now" ? 3 : p === "attend" ? 2 : p === "track" ? 1 : 0;
}

// Priority-first, then severity, then exploitation likelihood.
export function rankFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const p = priorityRank(b.priority) - priorityRank(a.priority);
    if (p) return p;
    const s = SEV_META[b.severity].rank - SEV_META[a.severity].rank;
    if (s) return s;
    return (b.epss ?? 0) - (a.epss ?? 0);
  });
}

export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0,
  };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

// CWE -> STRIDE (mirrors agent/graph.py).
const STRIDE_BY_CWE: Record<string, string> = {
  "CWE-287": "Spoofing", "CWE-290": "Spoofing", "CWE-384": "Spoofing", "CWE-346": "Spoofing",
  "CWE-89": "Tampering", "CWE-78": "Tampering", "CWE-79": "Tampering", "CWE-94": "Tampering",
  "CWE-22": "Tampering", "CWE-434": "Tampering", "CWE-502": "Tampering", "CWE-918": "Tampering",
  "CWE-778": "Repudiation", "CWE-117": "Repudiation",
  "CWE-200": "Information Disclosure", "CWE-798": "Information Disclosure",
  "CWE-311": "Information Disclosure", "CWE-312": "Information Disclosure",
  "CWE-522": "Information Disclosure", "CWE-259": "Information Disclosure",
  "CWE-400": "Denial of Service", "CWE-770": "Denial of Service",
  "CWE-834": "Denial of Service", "CWE-1333": "Denial of Service",
  "CWE-269": "Elevation of Privilege", "CWE-250": "Elevation of Privilege",
  "CWE-732": "Elevation of Privilege", "CWE-276": "Elevation of Privilege",
};

const CATEGORY_STRIDE: Record<Category, string> = {
  secret: "Information Disclosure",
  sast: "Tampering",
  dependency: "Elevation of Privilege",
  iac: "Elevation of Privilege",
  container: "Elevation of Privilege",
  misc: "Tampering",
};

export const STRIDE_ORDER = [
  "Spoofing", "Tampering", "Repudiation",
  "Information Disclosure", "Denial of Service", "Elevation of Privilege",
];

export function strideOf(f: Finding): string {
  for (const cwe of f.cwe ?? []) if (STRIDE_BY_CWE[cwe]) return STRIDE_BY_CWE[cwe];
  return CATEGORY_STRIDE[f.category];
}
