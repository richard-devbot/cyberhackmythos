"""Central, env-driven configuration for cyberhackmythos security controls.

Every knob here has a safe default. Operators override via environment variables
(prefixed ``CYBERHACKMYTHOS_``) so nothing security-relevant is hard-coded in source.

Design notes
------------
* **Env is scrubbed by allowlist, not denylist.** A child process (shell command
  or scanner) only ever sees the variables named in ``SHELL_ENV_ALLOWLIST``.
  Secrets like ``OPENAI_API_KEY`` are absent because they are never on the list —
  this is strictly safer than trying to enumerate every secret to strip.
* Values are parsed once at import time; the module is a settings snapshot.
"""

from __future__ import annotations

import os


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _get_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v not in (None, "") else default


def _get_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v in (None, ""):
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _get_int(name: str, default: int) -> int:
    v = os.getenv(name)
    try:
        return int(v) if v not in (None, "") else default
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    v = os.getenv(name)
    try:
        return float(v) if v not in (None, "") else default
    except ValueError:
        return default


def _get_list(name: str, default: list[str]) -> list[str]:
    v = os.getenv(name)
    if v in (None, ""):
        return list(default)
    return [item.strip() for item in v.split(",") if item.strip()]


# ---------------------------------------------------------------------------
# Sandbox / command execution
# ---------------------------------------------------------------------------

# Backend selection: "auto" (docker if available, else subprocess), "docker",
# "subprocess", or "none" (no isolation — emits a loud warning; test use only).
SANDBOX_BACKEND = _get_str("CYBERHACKMYTHOS_SANDBOX_BACKEND", "auto").lower()

# Container image used by the docker backend. Phase 1 will ship a purpose-built
# image with scanners baked in; slim python is enough for Phase 0 shell work.
SANDBOX_IMAGE = _get_str("CYBERHACKMYTHOS_SANDBOX_IMAGE", "python:3.13-slim")

# Whether sandboxed commands may reach the network. Default OFF — the single most
# important control against data exfiltration. Only the docker backend can truly
# enforce this; the subprocess backend cannot and says so.
SANDBOX_ALLOW_NETWORK = _get_bool("CYBERHACKMYTHOS_SANDBOX_ALLOW_NETWORK", False)

# Resource ceilings for a sandboxed command.
SANDBOX_CPU_SECONDS = _get_int("CYBERHACKMYTHOS_SANDBOX_CPU_SECONDS", 120)
SANDBOX_CPUS = _get_float("CYBERHACKMYTHOS_SANDBOX_CPUS", 1.0)
SANDBOX_WALL_SECONDS = _get_int("CYBERHACKMYTHOS_SANDBOX_WALL_SECONDS", 180)
SANDBOX_MEMORY_MB = _get_int("CYBERHACKMYTHOS_SANDBOX_MEMORY_MB", 1024)
SANDBOX_PIDS_LIMIT = _get_int("CYBERHACKMYTHOS_SANDBOX_PIDS_LIMIT", 256)
SANDBOX_FSIZE_MB = _get_int("CYBERHACKMYTHOS_SANDBOX_FSIZE_MB", 256)
SANDBOX_WORKDIR_MB = _get_int("CYBERHACKMYTHOS_SANDBOX_WORKDIR_MB", 512)
SANDBOX_USER = _get_str("CYBERHACKMYTHOS_SANDBOX_USER", "nobody")

# Variables the child process is allowed to inherit. Note the deliberate absence
# of anything secret. PATH/HOME/locale are enough for scanners and shell tools.
SHELL_ENV_ALLOWLIST = _get_list(
    "CYBERHACKMYTHOS_SHELL_ENV_ALLOWLIST",
    ["PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ", "TMPDIR"],
)

# Extra variables the *docker client* (outer process) needs to reach the daemon.
# These are only added to the outer env when the docker backend is active; they
# are never forwarded into the container.
DOCKER_CLIENT_ENV_ALLOWLIST = _get_list(
    "CYBERHACKMYTHOS_DOCKER_CLIENT_ENV_ALLOWLIST",
    ["DOCKER_HOST", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "DOCKER_CONTEXT"],
)


# ---------------------------------------------------------------------------
# fetch_webpage / SSRF controls
# ---------------------------------------------------------------------------

# Allow requests to private / loopback / link-local addresses. Default OFF to
# block SSRF against internal services and cloud metadata (169.254.169.254).
FETCH_ALLOW_PRIVATE = _get_bool("CYBERHACKMYTHOS_FETCH_ALLOW_PRIVATE", False)

# Route fetches through the r.jina.ai reader. Off by default: it leaks target
# URLs to a third party. When on, URLs are still validated locally first.
FETCH_USE_JINA = _get_bool("CYBERHACKMYTHOS_FETCH_USE_JINA", False)

FETCH_TIMEOUT_SECONDS = _get_float("CYBERHACKMYTHOS_FETCH_TIMEOUT_SECONDS", 20.0)
FETCH_MAX_BYTES = _get_int("CYBERHACKMYTHOS_FETCH_MAX_BYTES", 5_000_000)
FETCH_MAX_REDIRECTS = _get_int("CYBERHACKMYTHOS_FETCH_MAX_REDIRECTS", 5)
FETCH_ALLOWED_SCHEMES = _get_list("CYBERHACKMYTHOS_FETCH_ALLOWED_SCHEMES", ["http", "https"])


# ---------------------------------------------------------------------------
# Tool-result cache
# ---------------------------------------------------------------------------

# Upper bound on cached tool results (LRU eviction) to stop unbounded growth.
TOOL_CACHE_MAX_ENTRIES = _get_int("CYBERHACKMYTHOS_TOOL_CACHE_MAX_ENTRIES", 512)


# ---------------------------------------------------------------------------
# App auth / abuse limits
# ---------------------------------------------------------------------------

# Basic auth for the Gradio app as "user:pass" pairs, comma-separated.
# Empty => no auth (fine for localhost; set it for any shared deployment).
def _parse_auth(raw: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        user, pw = chunk.split(":", 1)
        if user and pw:
            pairs.append((user, pw))
    return pairs


APP_AUTH = _parse_auth(_get_str("CYBERHACKMYTHOS_APP_AUTH", ""))

# Cap on agent iterations per user turn (cost / DoS control).
MAX_ITERATIONS = _get_int("CYBERHACKMYTHOS_MAX_ITERATIONS", 60)


# ---------------------------------------------------------------------------
# Threat intelligence (Phase 2)
# ---------------------------------------------------------------------------
# Enrichment calls go OUT from the trusted app process to fixed public API
# hosts — never from inside the untrusted-code sandbox. Disable for fully
# air-gapped operation.
INTEL_ENABLED = _get_bool("CYBERHACKMYTHOS_INTEL_ENABLED", True)
INTEL_TIMEOUT_SECONDS = _get_float("CYBERHACKMYTHOS_INTEL_TIMEOUT_SECONDS", 15.0)
INTEL_CACHE_TTL_SECONDS = _get_int("CYBERHACKMYTHOS_INTEL_CACHE_TTL_SECONDS", 6 * 3600)

EPSS_API_URL = _get_str("CYBERHACKMYTHOS_EPSS_API_URL", "https://api.first.org/data/v1/epss")
KEV_FEED_URL = _get_str(
    "CYBERHACKMYTHOS_KEV_FEED_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
NVD_API_URL = _get_str("CYBERHACKMYTHOS_NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_API_KEY = _get_str("CYBERHACKMYTHOS_NVD_API_KEY", "")  # optional; raises rate limit
NVD_ENABLED = _get_bool("CYBERHACKMYTHOS_NVD_ENABLED", True)

# Priority thresholds (transparent, tunable). KEV always overrides to "act_now".
# EPSS is the probability of exploitation in the next 30 days (0..1).
EPSS_ACT_NOW = _get_float("CYBERHACKMYTHOS_EPSS_ACT_NOW", 0.5)
EPSS_ATTEND = _get_float("CYBERHACKMYTHOS_EPSS_ATTEND", 0.1)
CVSS_ATTEND = _get_float("CYBERHACKMYTHOS_CVSS_ATTEND", 7.0)


# ---------------------------------------------------------------------------
# Verified remediation (Phase 3)
# ---------------------------------------------------------------------------
# A patch fails verification if it introduces a finding at or above this severity
# floor. Strictly-lower-severity residuals (e.g. a LOW lint after fixing a HIGH)
# are reported but do not block — otherwise almost no real fix would ever verify.
REMEDIATION_REGRESSION_FLOOR = _get_str("CYBERHACKMYTHOS_REMEDIATION_REGRESSION_FLOOR", "high")


# ---------------------------------------------------------------------------
# Live testing / DAST — OFF by default, scoped to authorized hosts only.
# ---------------------------------------------------------------------------
# DAST reaches LIVE systems, so it stays disabled unless the operator both enables
# it AND lists the target host in the authorization allowlist. A scan of any host
# not on the list is refused. This is what keeps the tool from being pointed at
# systems you are not permitted to test — only run it against your own assets or
# targets you have written authorization for.
DAST_ENABLED = _get_bool("CYBERHACKMYTHOS_DAST_ENABLED", False)
# Comma-separated hostnames you are authorized to test, e.g. "dev.example.com,staging.example.com".
# A leading "." allows subdomains: ".example.com" authorizes any *.example.com host.
AUTHORIZED_TARGETS = _get_list("CYBERHACKMYTHOS_AUTHORIZED_TARGETS", [])
DAST_TIMEOUT_SECONDS = _get_int("CYBERHACKMYTHOS_DAST_TIMEOUT_SECONDS", 600)
