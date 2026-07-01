import type { Finding, ScanMeta } from "./types";

// Placeholder data so the dashboard renders standalone before the API is wired.
// Shapes match the Python engine's output exactly.
export const MOCK_FINDINGS: Finding[] = [
  {
    tool: "trivy", rule_id: "CVE-2021-44228", title: "Log4Shell — remote code execution in log4j-core",
    severity: "critical", category: "dependency", file: "pom.xml", package: "log4j-core",
    installed_version: "2.14.1", fixed_version: "2.15.0", cve: "CVE-2021-44228", cwe: ["CWE-502"],
    cvss_score: 10.0, epss: 0.99999, kev: true, kev_ransomware: true, priority: "act_now",
    remediation: "Upgrade log4j-core to 2.17.1+.",
  },
  {
    tool: "semgrep", rule_id: "python.django.security.sqli", title: "SQL injection via string-formatted query",
    severity: "high", category: "sast", file: "app/views.py", line: 142, cwe: ["CWE-89"],
    owasp: ["A03:2021 - Injection"], priority: "attend",
    remediation: "Use parameterized queries / the ORM.",
  },
  {
    tool: "bandit", rule_id: "B602", title: "subprocess call with shell=True",
    severity: "high", category: "sast", file: "tasks/run.py", line: 31, cwe: ["CWE-78"], priority: "attend",
    remediation: "Drop shell=True; pass an argument list.",
  },
  {
    tool: "gitleaks", rule_id: "aws-access-token", title: "AWS access key committed to source",
    severity: "high", category: "secret", file: "config/settings.py", line: 8, cwe: ["CWE-798"],
    priority: "attend", remediation: "Rotate the key and move it to a secret store.",
  },
  {
    tool: "trivy", rule_id: "CVE-2023-30861", title: "Flask session cookie information disclosure",
    severity: "medium", category: "dependency", file: "requirements.txt", package: "flask",
    installed_version: "2.2.2", fixed_version: "2.2.5", cve: "CVE-2023-30861", cwe: ["CWE-200"],
    cvss_score: 7.5, epss: 0.12, priority: "attend", remediation: "Upgrade Flask to 2.2.5+.",
  },
  {
    tool: "trivy", rule_id: "AVD-DS-0002", title: "Container image configured to run as root",
    severity: "medium", category: "iac", file: "Dockerfile", line: 1, priority: "track",
    remediation: "Add a non-root USER instruction.",
  },
  {
    tool: "hadolint", rule_id: "DL3008", title: "Pin apt package versions in Dockerfile",
    severity: "medium", category: "container", file: "Dockerfile", line: 5, priority: "track",
  },
  {
    tool: "semgrep", rule_id: "javascript.xss.react-danger", title: "dangerouslySetInnerHTML with untrusted input",
    severity: "medium", category: "sast", file: "web/components/Post.tsx", line: 54, cwe: ["CWE-79"],
    owasp: ["A03:2021 - Injection"], priority: "track",
  },
  {
    tool: "bandit", rule_id: "B105", title: "Possible hardcoded password string",
    severity: "low", category: "sast", file: "config/settings.py", line: 8, cwe: ["CWE-259"], priority: "track",
  },
  {
    tool: "bandit", rule_id: "B404", title: "Consider security implications of the subprocess module",
    severity: "low", category: "sast", file: "tasks/run.py", line: 2, cwe: ["CWE-78"], priority: "track",
  },
];

export const MOCK_META: ScanMeta = {
  target: "github.com/acme/payments-api",
  scanners: ["semgrep", "bandit", "gitleaks", "trivy", "hadolint"],
  isolation: "docker · network:none",
  scannedAt: "just now",
};
