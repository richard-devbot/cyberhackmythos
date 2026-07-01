// Mirrors the Python `Finding` model (agent/findings.py). This is the contract
// the frontend renders and, later, the API returns.

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";
export type Priority = "act_now" | "attend" | "track";
export type Category = "sast" | "secret" | "dependency" | "iac" | "container" | "misc";

export interface Finding {
  tool: string;
  rule_id: string;
  title: string;
  severity: Severity;
  category: Category;
  message?: string;
  file?: string | null;
  line?: number | null;
  cwe?: string[];
  owasp?: string[];
  cve?: string | null;
  package?: string | null;
  installed_version?: string | null;
  fixed_version?: string | null;
  cvss_score?: number | null;
  epss?: number | null;
  epss_percentile?: number | null;
  kev?: boolean;
  kev_ransomware?: boolean;
  priority?: Priority | null;
  remediation?: string | null;
}
