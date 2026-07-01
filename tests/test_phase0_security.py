"""Phase 0 security regression tests.

These lock in the controls that break the inject -> execute -> exfiltrate chain:
environment scrubbing, SSRF blocking, sandbox isolation reporting, and cache
bounding. If any of these regress, CI fails.
"""

import os

import pytest

from agent import config, sandbox, netguard
from agent.netguard import UrlNotAllowed, validate_public_url
from agent.tools import _BoundedCache


# ---------------------------------------------------------------------------
# Environment scrubbing (fixes secret-leak: os.environ.copy() -> allowlist)
# ---------------------------------------------------------------------------

def test_build_child_env_excludes_secrets(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "SENTINEL_SECRET")
    monkeypatch.setenv("HF_TOKEN", "hf_sentinel")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    env = sandbox.build_child_env()
    assert "OPENAI_API_KEY" not in env
    assert "HF_TOKEN" not in env
    assert env.get("PATH") == "/usr/bin:/bin"


def test_build_child_env_custom_allowlist(monkeypatch):
    monkeypatch.setenv("MY_ALLOWED", "yes")
    monkeypatch.setenv("MY_SECRET", "no")
    env = sandbox.build_child_env(allowlist=["MY_ALLOWED"])
    assert env == {"MY_ALLOWED": "yes"}


# ---------------------------------------------------------------------------
# SSRF guard (fixes fetch_webpage reaching internal / metadata endpoints)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://[::1]/",
        "http://100.64.0.1/",  # CGNAT
        "file:///etc/passwd",  # disallowed scheme
        "ftp://example.com/",  # disallowed scheme
        "http://0.0.0.0/",
    ],
)
def test_ssrf_blocks_dangerous_urls(url):
    with pytest.raises(UrlNotAllowed):
        validate_public_url(url)


def test_ssrf_allows_public(monkeypatch):
    # Avoid depending on live DNS; pin the resolver to a public address.
    monkeypatch.setattr(netguard, "_resolve_all", lambda host: ["93.184.216.34"])
    validate_public_url("https://example.com/path")  # must not raise


def test_ssrf_blocks_when_any_ip_private(monkeypatch):
    # A host that resolves to both a public and a private IP must be rejected.
    monkeypatch.setattr(netguard, "_resolve_all", lambda host: ["93.184.216.34", "127.0.0.1"])
    with pytest.raises(UrlNotAllowed):
        validate_public_url("https://sneaky.example/")


# ---------------------------------------------------------------------------
# Sandbox reporting is honest about the active tier
# ---------------------------------------------------------------------------

def test_sandbox_reports_isolation(monkeypatch):
    monkeypatch.setattr(config, "SANDBOX_BACKEND", "subprocess")
    sb = sandbox.Sandbox()
    assert sb.backend == "subprocess"
    assert "NO network isolation" in sb.isolation_level


def test_docker_tier_has_isolation_flags(monkeypatch):
    """The docker argv must carry every isolation flag (locks the tier config)."""
    monkeypatch.setattr(config, "SANDBOX_BACKEND", "docker")
    sb = sandbox.Sandbox()
    prepared = sb.prepare("echo hi", "/tmp/work123")
    argv = " ".join(prepared.args)
    assert prepared.shell is False
    assert prepared.network_enforced is True
    for flag in (
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "-u nobody",
        "--pids-limit",
        "-v /tmp/work123:/work:rw",
    ):
        assert flag in argv, f"missing isolation flag: {flag}"


def test_docker_container_gets_no_host_env(monkeypatch):
    """Docker never forwards host env into the container (secrets stay out)."""
    monkeypatch.setenv("OPENAI_API_KEY", "SENTINEL_SECRET")
    monkeypatch.setattr(config, "SANDBOX_BACKEND", "docker")
    sb = sandbox.Sandbox()
    prepared = sb.prepare("echo hi", "/tmp/work123")
    # The outer docker client env is allowlisted and never includes secrets;
    # `docker run` here uses no -e flags, so the container inherits nothing.
    assert "OPENAI_API_KEY" not in prepared.env
    assert "-e" not in prepared.args


# ---------------------------------------------------------------------------
# Bounded tool-result cache
# ---------------------------------------------------------------------------

def test_bounded_cache_evicts_oldest():
    c = _BoundedCache(2)
    c["a"], c["b"] = "1", "2"
    c["c"] = "3"
    assert "a" not in c
    assert set(c.keys()) == {"b", "c"}


# ---------------------------------------------------------------------------
# End-to-end: a shell command cannot read the API key (the whole point)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(os.name != "posix", reason="subprocess sandbox is POSIX-only")
def test_shell_command_cannot_read_api_key(monkeypatch):
    import time

    monkeypatch.setenv("OPENAI_API_KEY", "SENTINEL_SECRET_XYZ")
    monkeypatch.setattr(config, "SANDBOX_BACKEND", "subprocess")

    from agent.shell import ShellManager

    mgr = ShellManager(sandbox=sandbox.Sandbox())
    try:
        mgr.start("secret-test", "env; echo MARKER_DONE")
        deadline = time.time() + 5
        out = ""
        while time.time() < deadline:
            out = mgr.get_output("secret-test") or ""
            if "MARKER_DONE" in out:
                break
            time.sleep(0.1)
        # env ran (sanity) but the secret is absent from the scrubbed environment.
        assert "PATH=" in out
        assert "SENTINEL_SECRET_XYZ" not in out
    finally:
        mgr.close_all()
