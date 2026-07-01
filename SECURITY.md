# cyberhackmythos Security Model

cyberhackmythos runs an LLM agent that executes commands and fetches URLs while analyzing
**untrusted** code. This document describes the controls that keep that safe. It reflects
**Phase 0** of `docs/UPGRADE_PLAN.md`.

## Threat model

The agent's context is fed untrusted input (pasted code, fetched web pages, MCP results),
and the agent can run shell commands. The primary threats are:

1. **Indirect prompt injection → command execution** — untrusted content instructs the agent
   to run attacker-chosen commands.
2. **Secret exfiltration** — a command reads `OPENAI_API_KEY` (or other secrets) and sends it out.
3. **SSRF** — `fetch_webpage` is pointed at internal services or cloud metadata (`169.254.169.254`).
4. **Resource exhaustion / cost abuse** — runaway loops or fork bombs.
5. **Unauthenticated access** — anyone reaching the app inherits the shell.

## Controls (Phase 0)

| Control | Where | Effect |
|---|---|---|
| **Env scrubbing (allowlist)** | `agent/sandbox.py: build_child_env` | Commands only ever see allowlisted vars (PATH/HOME/locale). Secrets are **never** present, so they cannot be exfiltrated even if a command tries. Holds in **every** tier. |
| **Sandbox tiers** | `agent/sandbox.py` | `docker` (network-none, read-only rootfs, `--cap-drop ALL`, `no-new-privileges`, non-root, cpu/mem/pids limits) → `subprocess` (scrubbed env + `setrlimit` CPU/mem/fsize) → `none` (warns). |
| **SSRF guard** | `agent/netguard.py` | Every fetched URL is scheme-checked and all resolved IPs must be public; private/loopback/link-local/CGNAT are blocked. Redirects are re-validated per hop. |
| **Iteration cap** | `agent/agent.py`, `CYBERHACKMYTHOS_MAX_ITERATIONS` | Bounds agent turns per message (default 60). |
| **Bounded tool cache** | `agent/tools.py: _BoundedCache` | LRU eviction; no unbounded growth or cross-session retention. |
| **App auth** | `app.py`, `CYBERHACKMYTHOS_APP_AUTH` | Basic auth; a startup warning fires when unset. |
| **Output escaping** | `app.py` | Model/error text is HTML-escaped before rendering. |
| **Dependency pinning + audit** | `requirements.txt`, `.github/workflows/ci.yml` | Pinned versions; `pip-audit` in CI. |

## Isolation tiers — what each guarantees

- **docker** *(auto-selected when a daemon is reachable):* the strongest tier. `--network none`
  means a compromised command cannot reach the internet or internal network at all — the
  decisive anti-exfiltration control. The container inherits no host env.
- **subprocess** *(POSIX fallback, e.g. Hugging Face Spaces where DinD is unavailable):* env is
  scrubbed and CPU/memory/file-size are capped, **but network egress cannot be blocked without
  namespaces**. The exfiltration risk is still largely defused because the secret is not in the
  scrubbed env. `Sandbox.isolation_level` states this plainly; the app prints it at startup.
- **none:** no isolation; emits a loud warning. Test use only.

Check the active tier: it is printed at startup (`[cyberhackmythos] Sandbox backend=…`).

## Operator guidance

- Set `CYBERHACKMYTHOS_APP_AUTH` for any shared/public deployment.
- Prefer the docker backend in production; keep `CYBERHACKMYTHOS_SANDBOX_ALLOW_NETWORK=false`.
- Rotate the model API key if it is ever exposed.

## Known limitations (tracked for later phases)

- **DNS rebinding (TOCTOU)** between SSRF validation and connect — closed by pinning the
  validated IP into the connection (Phase 1).
- **Network egress in the subprocess tier** is not blocked — use docker where egress control matters.
- MCP server responses are not yet validated/sandboxed (Phase 1).

## Reporting a vulnerability

Please open a private security advisory rather than a public issue.
