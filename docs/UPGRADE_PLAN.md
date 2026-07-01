# OpenMythos Upgrade Plan

**Goal:** evolve OpenMythos from an LLM-with-a-shell into a security testing tool that
professionals trust — broad audience (AppSec/pentesters, DevSecOps, researchers).

**Guiding principle:** trust is the product. Experts will (a) feed it *malicious* code and
(b) refuse to act on unverified guesses. The plan is sequenced to earn trust before adding reach.

**Status of model wiring:** ✅ migrated to NVIDIA NIM (`z-ai/glm-5.1`). Chat + tool-calling
verified live. Config is env-driven (`.env`); no secrets in tracked source.

---

## Part 1 — Security audit of the current app

The current app is, ironically, the kind of target it's meant to find flaws in. Evidence below
is from the code as it stands. Severities are qualitative (Critical = trivially exploitable +
high impact).

| # | Severity | Finding | Evidence | CWE |
|---|----------|---------|----------|-----|
| 1 | **Critical** | **Unsandboxed arbitrary command execution.** The `shell` tool runs any command with `shell=True`; the only isolation is a temp `cwd`. On a public Space this is RCE-as-a-service. | `agent/shell.py:138-148` (`subprocess.Popen(command, shell=True, ...)`), exposed via `agent/tools.py:257-280` | CWE-78 |
| 2 | **Critical** | **Secrets leak to agent-run shells.** The subprocess inherits the full parent environment, so any command (`env`, `printenv`) can read `OPENAI_API_KEY` (your `nvapi-` key) and exfiltrate it. | `agent/shell.py:132-134` (`process_env = os.environ.copy()`) | CWE-200 / CWE-526 |
| 3 | **Critical** | **Indirect prompt injection → RCE.** Untrusted content (pasted code, fetched web pages, MCP results) enters the model context with no data/instruction separation, and the model holds `shell`. A malicious repo can instruct the agent to run commands. | `agent/tools.py:154-167` (`fetch_webpage`) + `shell` tool + `agent/agent.py` loop | CWE-77 / CWE-94 |
| 4 | **High** | **SSRF in `fetch_webpage`.** Fetches arbitrary URLs (jina proxy, then `MarkItDown().convert(url)` fallback) with no allowlist — internal hosts and cloud metadata (`169.254.169.254`) are reachable. Also leaks target URLs to a third-party proxy. | `agent/tools.py:160-167` | CWE-918 |
| 5 | **High** | **No authentication on a tool that grants shell.** `launch()` has no `auth=`; anyone who reaches the Space gets findings #1–#3. | `app.py` → `demo.queue(...).launch(...)` (no `auth`) | CWE-306 |
| 6 | **Medium** | **Unpinned dependencies, no lockfile, no audit.** `gradio/openai/python-dotenv/markitdown` float to latest — supply-chain + non-reproducible builds. | `requirements.txt` | CWE-1104 |
| 7 | **Medium** | **No audit logging / egress control.** Tool calls (shell commands, fetched URLs) aren't logged server-side; abuse is undetectable and exfiltration unimpeded. | absence across `agent/` | CWE-778 |
| 8 | **Medium** | **Unbounded global tool-result cache.** `_TOOL_RESULTS_CACHE` is a process-global dict keyed by `tool_call_id`, never evicted — memory growth + cross-session data retention. | `agent/tools.py:284` | CWE-401 |
| 9 | **Medium** | **DoS / cost amplification.** Each user turn can drive up to 150 model iterations, each able to spawn shell commands, with no per-user quota or shell resource caps. | `agent/agent.py` (`max_iterations=150`), `agent/shell.py` (no CPU/mem cap) | CWE-400 |
| 10 | **Low** | **Untrusted MCP servers trusted implicitly.** Startup connects to 4 external MCP servers and feeds their responses to the model unvalidated; startup silently degrades if they're down. | `agent/mcp.py:244-265`, `app.py` → `agent.register_all_mcp()` | CWE-829 |
| 11 | **Low** | **Raw exception/model text rendered into HTML.** Error spans embed `{exc}`/`{ev['content']}` into HTML-rendered markdown bubbles — HTML-injection surface. | `app.py` `stream_response` error branches | CWE-79 |
| 12 | **Low** | **Sensitive code persisted to browser localStorage** unencrypted (conversation history includes pasted source). | `app.py` JS save/load (`storage.save.js`/`storage.load.js`) | CWE-922 |

**Bottom line:** findings #1–#3 form one exploit chain (inject → execute → exfiltrate the API
key) and must close together in Phase 0 before any public-facing capability work.

---

## Part 2 — Target architecture

New/changed modules (additive; existing agent loop stays the orchestrator):

```
agent/
  config.py          # central env-driven config, allowlists, sandbox mode
  sandbox.py         # execution isolation (container/nsjail; subprocess fallback)
  findings.py        # normalized Finding model, dedup/merge, SARIF export
  intel.py           # CVE enrichment: NVD / OSV / GHSA + CVSS / EPSS / CISA KEV
  graph.py           # dependency risk graph built from SBOM
  remediation.py     # patch -> apply-in-sandbox -> re-scan -> test loop
  report.py          # SARIF / HTML / Markdown / PDF reports
  scanners/
    base.py          # Scanner -> Tool adapter; emits normalized Findings
    semgrep.py bandit.py gosec.py     # SAST
    secrets.py                        # gitleaks / trufflehog / detect-secrets
    sca.py sbom.py                    # OSV-Scanner / Trivy / Syft
    iac.py                            # Checkov / hadolint
cli.py               # headless: scan a path/repo, emit SARIF (CI-friendly)
eval/                # benchmark harness vs held-out BigVul/CVE
tests/               # pytest suite (unit + injection/sandbox regression tests)
.github/workflows/   # GitHub Action + self-scan (dogfood)
docs/                # this plan, security policy, runbook
```

Normalized **Finding** (the contract every scanner and the model speak):
`id, title, severity, cwe, owasp, cvss, epss, kev, file, line, snippet, source_tool, confidence, status, remediation`.

---

## Part 3 — Phased implementation plan

Each phase ends shippable. Commits bisected per repo convention (mechanical vs behavior vs new feature separated). Every phase adds tests.

### Phase 0 — Foundation & safety *(blocking; closes #1–#9)* — ✅ DONE
**Why first:** the tool's whole premise is analyzing hostile code; it must survive that.

Delivered on `feat/phase0-sandbox`: `agent/config.py` (env-driven controls), `agent/sandbox.py`
(tiered docker/subprocess isolation + env scrubbing), `agent/netguard.py` (SSRF guard),
integrated into `agent/shell.py` and `agent/tools.py`; `app.py` gains auth + iteration cap +
output escaping; pinned `requirements.txt` + `pip-audit`/ruff/pytest CI; `SECURITY.md`;
20 regression tests (`tests/test_phase0_security.py`, all passing). The original items:
- `agent/sandbox.py`: run shell + scanners in an isolated context — **no network egress**, read-only FS except a scratch mount, dropped capabilities, CPU/mem/wall-clock limits. Docker primary; `nsjail`/`firejail` and a restricted-subprocess fallback for envs without Docker.
- `agent/shell.py`: stop inheriting secrets — build a minimal env allowlist; never pass `OPENAI_API_KEY`.
- `agent/tools.py` `fetch_webpage`: URL validation — block private/loopback/link-local ranges + metadata IPs; scheme allowlist (`http`/`https`); size cap.
- `app.py`: optional `auth=` + per-session rate limiting; HTML-escape error/model text before embedding in bubbles.
- `agent/tools.py`: bound `_TOOL_RESULTS_CACHE` (LRU + per-conversation namespace).
- `requirements.txt`: pin versions + add lockfile; add `pip-audit` to CI.
- **Acceptance:** an injection-regression test (malicious repo that tries `env`/exfil) cannot read the API key or reach the network; pip-audit clean.

### Phase 1 — Real scanning engine *(guesses → evidence)* — ✅ DONE
- `agent/findings.py`: normalized `Finding` model + `Severity`/`Category`, cross-tool dedup/merge, severity histogram, **SARIF 2.1.0** export.
- `agent/scanners/`: `base.py` (Scanner ABC, sandboxed execution, missing-binary handling, Tool adapters, findings store) + five scanners — **Semgrep** (SAST), **Bandit** (Python SAST), **gitleaks** (secrets), **Trivy** (SCA/IaC/secrets), **hadolint** (Dockerfile).
- `agent/workspace.py`: per-run workspace with path-traversal guard; `write_file`, `scan_all`, `export_sarif` tools registered in `app.py`; system prompt rewritten around evidence-first scanning.
- `Dockerfile.scanners`: purpose-built image with all tools + rules/DB pre-baked so scans run under `--network none`.
- **Acceptance:** 21 new tests (parsers vs real sample output, dedup, SARIF, workspace, missing-binary) + a **live end-to-end bandit scan** of vulnerable code producing correct CWE-tagged findings. All 41 tests green.
- Follow-ons (not blocking): osv-scanner, Checkov, gosec, Syft SBOM; DNS-rebind pinning.

### Phase 2 — Intelligence layer *(the README's real promises)* — ✅ DONE
- `agent/intel.py`: `EPSSClient` (FIRST), `KEVCatalog` (CISA, cached), `NVDClient` (CVSS v3.1/3.0/2), and a `ThreatIntel` orchestrator that enriches CVE findings with **EPSS + CISA KEV + CVSS** and a transparent `score_priority` matrix (act_now / attend / track; KEV overrides; thresholds in config). Enrichment runs in the trusted app process against fixed public hosts — never in the untrusted-code sandbox.
- `agent/graph.py`: `build_risk_graph` (Mermaid risk map, priority-colored), `priority_table`, and CWE→**STRIDE** categorization. (Full transitive tree via Syft SBOM = documented follow-on.)
- `agent/intel_tools.py`: `enrich_findings`, `threat_report`, `risk_graph` tools registered in `app.py`; prompt updated with the enrichment step.
- **Acceptance:** 19 new tests (client parsing, priority matrix, STRIDE, graph, end-to-end enrichment) + a **live run against the real EPSS/KEV/NVD APIs**: Log4Shell → EPSS 99.999%, CVSS 10.0, KEV+ransomware → `act_now`; low-risk CVE → `track`. All 60 tests green.
- Follow-ons: OSV/GHSA detail lookups, Syft SBOM for the transitive graph, EPSS caching.

### Phase 3 — Verified remediation *(the missing half)* — ✅ DONE
- `agent/remediation.py`: `RemediationVerifier` snapshots the workspace, applies a unified diff in the sandbox (git apply → patch fallback), re-scans the isolated copy, and compares finding sets by line-independent `match_key`. Reports resolved, **blocking regressions** (at/above a configurable severity floor) vs non-blocking lower-severity residuals, and optional test-command result. Original workspace is never mutated.
- `Finding.match_key()`: line-independent identity so a patch's line shifts don't read as resolved+introduced.
- `verify_patch` tool registered in `app.py`; prompt now **requires** verifying every patch before presenting it as fixed.
- **Acceptance:** 11 new tests including a **live end-to-end**: real bandit baseline → apply a genuine `shell=True` fix → re-scan → `✅ PATCH VERIFIED; resolved 1; 1 lower-severity residual (non-blocking)`, with the original left untouched. All 70 tests green.
- Design note: a strict "any new finding fails" rule was rejected — almost every real fix trips a lower-severity lint (e.g. bandit B603 after removing B602). The regression *floor* (default HIGH) is the defensible rule.

### Phase 4 — Reporting & standards
- `agent/report.py`: **SARIF** (GitHub Code Scanning compatible) + HTML/Markdown/PDF; map every finding to CWE / OWASP Top 10 / ASVS; severity-ranked with remediation.
- **Acceptance:** SARIF validates and uploads to GitHub Code Scanning; PDF/HTML render the full report.

### Phase 5 — Where experts work
- `cli.py`: `openmythos scan <path|git-url> --sarif out.sarif` (headless, exit-code on severity threshold).
- `.github/workflows/`: reusable Action + PR-comment bot; **self-scan job (dogfood)**.
- Minimal REST API for programmatic use.
- **Acceptance:** the Action runs on a PR and posts findings as comments; CLI exits non-zero above threshold.

### Phase 6 — Quality & proof
- Adversarial verifier agent: a second pass that tries to *refute* each finding to cut false positives.
- `eval/`: benchmark harness measuring detection rate / FP rate against held-out BigVul/CVE; publish the numbers.
- **Acceptance:** reproducible benchmark report with precision/recall the README can cite.

---

## Sequencing & dependencies

```
Phase 0  ──>  Phase 1  ──>  Phase 2  ──>  Phase 3  ──>  Phase 4  ──>  Phase 5
  (safe)      (scan)        (intel)       (verify)      (report)      (integrate)
                                                                         │
                                                              Phase 6 (quality) runs alongside 3–5
```

Phase 0 gates everything (scanners and patch-apply execute untrusted tooling). Phases 1→4 are a
straight dependency chain. Phase 6 starts as soon as there are findings to verify (after Phase 1).

## First concrete steps (when we start building)
1. Branch `feat/phase0-sandbox` off `main`.
2. Add `agent/config.py` + `agent/sandbox.py` with a Docker-first executor and subprocess fallback.
3. Cut `os.environ.copy()` over to an env allowlist in `agent/shell.py`.
4. Add the injection-regression test that asserts the API key is unreachable.
5. Pin `requirements.txt` + wire `pip-audit` into a CI workflow.
