---
title: cyberhackmythos
emoji: 🛡️
colorFrom: gray
colorTo: indigo
sdk: gradio
sdk_version: 6.19.0
python_version: '3.13'
app_file: app.py
pinned: true
short_description: An AI security agent that audits code with real scanners, prioritizes with live threat intel, and verifies its own patches.
license: apache-2.0
---

# cyberhackmythos 🛡️

**Paste a codebase. cyberhackmythos audits it with real security scanners, enriches every
finding with live threat intelligence, ranks what to fix first, and proves its patches
actually work — before it ever calls something "fixed."**

It runs an LLM agent (NVIDIA NIM / `nemotron-3-nano`, or a self-hosted security model) inside a locked-down sandbox and gives it
a toolbox of industry-standard scanners plus a threat-intel layer. The result is
**evidence, not guesses**: each finding is backed by a real tool, a CWE/CVE, and a
defensible priority — and each hotfix is verified by re-scanning before it's shown to you.

> ⚠️ **Defensive security.** cyberhackmythos is built to *find and fix* flaws in your own
> code — SAST issues, hardcoded secrets, vulnerable dependencies, IaC/container
> misconfigurations — so you can ship fixes before they're exploited.

---

## What makes it different

Most "AI security" demos just ask a model to eyeball code. cyberhackmythos is engineered
so its output can be trusted:

| Capability | How it works |
|---|---|
| 🔒 **Sandboxed execution** | Every command/scanner runs isolated — Docker (`--network none`, read-only rootfs, dropped caps, non-root) or a resource-limited subprocess fallback. The child environment is scrubbed to an allowlist, so **secrets are never reachable** by analyzed code. |
| 🧰 **Real scanners** | Semgrep & Bandit (SAST), gitleaks (secrets), Trivy (dependency CVEs / IaC / secrets), hadolint (Dockerfiles) — all normalized into one finding model with cross-tool dedup and **SARIF 2.1.0** export. |
| 📊 **Live threat intel** | Each CVE is enriched with **EPSS** (exploitation probability), **CISA KEV** (known-exploited-in-the-wild), and **CVSS** (NVD), then assigned a transparent priority: `act_now` / `attend` / `track`. |
| 🩹 **Verified patches** | A fix is applied to an isolated copy, the code is **re-scanned**, and the patch is only trusted if the finding is gone with no higher-or-equal-severity regression. No unverified patches. |
| 🗺️ **Prioritized reporting** | STRIDE categorization, a Mermaid risk map, and a ranked priority table lead with what's actually being exploited. |

See [`SECURITY.md`](SECURITY.md) for the full threat model and isolation tiers, and
[`docs/UPGRADE_PLAN.md`](docs/UPGRADE_PLAN.md) for the engineering roadmap.

---

## Quickstart

```bash
git clone https://github.com/richard-devbot/cyberhackmythos.git
cd cyberhackmythos
pip install -r requirements.txt

cp .env.example .env      # then edit .env with your model key
python app.py
```

Configure the model and controls in `.env` (see `.env.example` for every knob):

```ini
OPENAI_API_KEY=nvapi-your-key-here
OPENAI_BASE_URL=https://integrate.api.nvidia.com/v1
OPENAI_MODEL=nvidia/nemotron-3-nano-30b-a3b
```

**For any shared/public deployment**, set app auth and prefer the Docker sandbox:

```ini
CYBERHACKMYTHOS_APP_AUTH=analyst:choose-a-strong-password
CYBERHACKMYTHOS_SANDBOX_BACKEND=docker
```

Build the scanner image once so scans run fully offline (network-none):

```bash
docker build -f Dockerfile.scanners -t cyberhackmythos-scanners:latest .
export CYBERHACKMYTHOS_SANDBOX_IMAGE=cyberhackmythos-scanners:latest
```

---

## How the agent works

1. **Stage** — pasted code is written into a path-traversal-guarded workspace.
2. **Scan** — `scan_all` runs every available scanner in the sandbox → normalized findings.
3. **Enrich** — `enrich_findings` attaches EPSS + CISA KEV + CVSS and a priority.
4. **Explain & patch** — each real finding gets an impact write-up and a unified-diff hotfix.
5. **Verify** — `verify_patch` applies the diff to an isolated copy and re-scans to prove it.
6. **Report** — `threat_report` / `risk_graph` / `export_sarif` for prioritized output.

---

## Testing

```bash
pip install -r requirements-dev.txt
pytest -q          # unit + security regression + scanner-parser tests
ruff check .
pip-audit -r requirements.txt
```

CI (`.github/workflows/ci.yml`) runs `pip-audit`, `ruff`, and the test suite on every push/PR.

---

## Credits & license

cyberhackmythos is licensed under **Apache-2.0** (see [`LICENSE`](LICENSE)).

The security engine — sandboxing, the scanner integration layer, the threat-intelligence
and prioritization system, and the verified-remediation loop — was designed and built by
**Richardson Gunde**.

It builds on the original **OpenMythos** demo (Hugging Face Small Gradio Hackathon) by
KingNish and Himanshu, which is also Apache-2.0. See [`NOTICE`](NOTICE) for attribution.
