"""Command execution isolation for OpenMythos.

The agent runs commands on behalf of an LLM that is analyzing *untrusted* code.
Those commands must not be able to (a) read secrets, (b) exfiltrate data over the
network, or (c) exhaust the host. This module centralizes how a command is turned
into a concrete process so every execution path gets the same guarantees.

Isolation tiers (best first)
----------------------------
``docker``
    Full isolation: ``--network none`` (no egress), read-only root fs, dropped
    capabilities, ``no-new-privileges``, non-root user, and cpu/mem/pids limits.
    The container inherits **none** of the host env, so secrets cannot leak
    regardless of what the command does.

``subprocess``
    POSIX fallback with a scrubbed (allowlisted) environment and ``setrlimit``
    ceilings on CPU, memory, processes, and file size. **Cannot** block network
    egress by itself — this is reported honestly via ``isolation_level``. Secrets
    are still protected because the env is scrubbed to an allowlist.

``none``
    No isolation. Emits a loud warning. For controlled test environments only.

The two guarantees that hold in *every* tier are the ones that break the current
inject -> execute -> exfiltrate-the-API-key chain: the environment is scrubbed to
an allowlist, and the working directory is a caller-provided scratch space.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass

from . import config

_POSIX = os.name == "posix"
_IS_LINUX = sys.platform.startswith("linux")


# ---------------------------------------------------------------------------
# Environment scrubbing
# ---------------------------------------------------------------------------

def build_child_env(allowlist: list[str] | None = None, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Return an env dict containing only allowlisted variables from the host.

    Secrets are never included because they are not on the allowlist. ``extra``
    is merged last for values the caller explicitly wants present.
    """
    names = allowlist if allowlist is not None else config.SHELL_ENV_ALLOWLIST
    env = {name: os.environ[name] for name in names if name in os.environ}
    if extra:
        env.update(extra)
    return env


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

_docker_ok: bool | None = None


def _docker_available() -> bool:
    """True if a docker client can reach a running daemon. Cached."""
    global _docker_ok
    if _docker_ok is not None:
        return _docker_ok
    if not shutil.which("docker"):
        _docker_ok = False
        return False
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            timeout=8,
            env=build_child_env(extra={"PATH": os.environ.get("PATH", "")}),
        )
        _docker_ok = proc.returncode == 0
    except Exception:
        _docker_ok = False
    return _docker_ok


def resolve_backend() -> str:
    """Resolve the configured backend to a concrete one for this host."""
    choice = config.SANDBOX_BACKEND
    if choice == "docker":
        return "docker"  # honor explicit request even if detection is imperfect
    if choice == "subprocess":
        return "subprocess"
    if choice == "none":
        return "none"
    # auto
    if _docker_available():
        return "docker"
    return "subprocess"


# ---------------------------------------------------------------------------
# Prepared command
# ---------------------------------------------------------------------------

@dataclass
class PreparedCommand:
    """Everything ``subprocess.Popen`` needs, resolved by the sandbox."""

    args: str | list[str]
    shell: bool
    env: dict[str, str]
    cwd: str
    preexec_fn: object | None  # Callable | None; typed loosely to avoid import churn
    isolation_level: str
    network_enforced: bool


@dataclass
class SandboxResult:
    """Outcome of a one-shot sandboxed command."""

    stdout: str
    stderr: str
    returncode: int
    timed_out: bool
    isolation_level: str
    network_enforced: bool


def _rlimit_preexec():
    """Build a preexec_fn that applies resource ceilings (POSIX only)."""
    import resource

    cpu = config.SANDBOX_CPU_SECONDS
    mem_bytes = config.SANDBOX_MEMORY_MB * 1024 * 1024
    fsize_bytes = config.SANDBOX_FSIZE_MB * 1024 * 1024

    def _apply() -> None:  # pragma: no cover - runs in the child process
        # Per-process, portable limits only.
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        except Exception:
            pass
        try:
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        except Exception:
            pass
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_bytes, fsize_bytes))
        except Exception:
            pass
        # NOTE: RLIMIT_NPROC is intentionally NOT set here. On macOS/BSD it is a
        # per-*user* limit, so lowering it below the user's current process count
        # makes every fork() fail. Process-count capping is a docker-tier control
        # (`--pids-limit`); the subprocess fallback cannot enforce it safely.
        # Detach into a new session so the whole group can be killed together.
        try:
            os.setsid()
        except Exception:
            pass

    return _apply


class Sandbox:
    """Turns a command string + workdir into an isolated :class:`PreparedCommand`."""

    def __init__(self) -> None:
        self.backend = resolve_backend()

    # -- reporting ---------------------------------------------------------
    @property
    def isolation_level(self) -> str:
        if self.backend == "docker":
            net = "network:host" if config.SANDBOX_ALLOW_NETWORK else "network:none"
            return f"docker ({net}, read-only rootfs, caps dropped, non-root)"
        if self.backend == "subprocess":
            return "process (env scrubbed + rlimits; NO network isolation)"
        return "none (UNSAFE — no isolation)"

    def describe(self) -> str:
        return f"Sandbox backend={self.backend}; isolation={self.isolation_level}"

    # -- preparation -------------------------------------------------------
    def prepare(self, command: str, workdir: str, network: bool | None = None) -> PreparedCommand:
        allow_net = config.SANDBOX_ALLOW_NETWORK if network is None else network
        if self.backend == "docker":
            return self._prepare_docker(command, workdir, allow_net)
        if self.backend == "subprocess":
            return self._prepare_subprocess(command, workdir, allow_net)
        return self._prepare_none(command, workdir)

    def _prepare_docker(self, command: str, workdir: str, allow_net: bool) -> PreparedCommand:
        args = [
            "docker", "run", "--rm", "-i",
            "--network", ("host" if allow_net else "none"),
            "--read-only",
            "--tmpfs", "/tmp:rw,size=64m",
            "--memory", f"{config.SANDBOX_MEMORY_MB}m",
            "--memory-swap", f"{config.SANDBOX_MEMORY_MB}m",
            "--cpus", str(config.SANDBOX_CPUS),
            "--pids-limit", str(config.SANDBOX_PIDS_LIMIT),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-u", config.SANDBOX_USER,
            "-w", "/work",
            "-v", f"{workdir}:/work:rw",
            config.SANDBOX_IMAGE,
            "sh", "-c", command,
        ]
        # Outer process (the docker client) needs PATH + daemon-locating vars.
        env = build_child_env(
            allowlist=config.SHELL_ENV_ALLOWLIST + config.DOCKER_CLIENT_ENV_ALLOWLIST
        )
        return PreparedCommand(
            args=args,
            shell=False,
            env=env,
            cwd=workdir,
            preexec_fn=None,
            isolation_level=self.isolation_level,
            network_enforced=not allow_net,
        )

    def _prepare_subprocess(self, command: str, workdir: str, allow_net: bool) -> PreparedCommand:
        env = build_child_env()
        return PreparedCommand(
            args=command,
            shell=True,
            env=env,
            cwd=workdir,
            preexec_fn=_rlimit_preexec() if _POSIX else None,
            isolation_level=self.isolation_level,
            network_enforced=False,  # cannot enforce without namespaces
        )

    # -- one-shot execution ------------------------------------------------
    def run_capture(
        self,
        command: str,
        workdir: str,
        timeout: float | None = None,
        network: bool | None = None,
    ) -> SandboxResult:
        """Run *command* to completion in the sandbox and capture its output.

        This is the primitive scanners (Phase 1) and patch verification (Phase 3)
        use — unlike the interactive shell, it blocks until the process exits and
        returns stdout/stderr separately (scanners emit JSON on stdout).
        """
        prepared = self.prepare(command, workdir, network)
        wall = timeout if timeout is not None else config.SANDBOX_WALL_SECONDS
        try:
            proc = subprocess.run(
                prepared.args,
                shell=prepared.shell,
                env=prepared.env,
                cwd=prepared.cwd,
                preexec_fn=prepared.preexec_fn,
                capture_output=True,
                text=True,
                timeout=wall,
            )
            return SandboxResult(
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                returncode=proc.returncode,
                timed_out=False,
                isolation_level=prepared.isolation_level,
                network_enforced=prepared.network_enforced,
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(
                stdout=(exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr=f"command timed out after {wall}s",
                returncode=124,
                timed_out=True,
                isolation_level=prepared.isolation_level,
                network_enforced=prepared.network_enforced,
            )

    def _prepare_none(self, command: str, workdir: str) -> PreparedCommand:
        print(
            "[sandbox] WARNING: backend='none' — commands run with NO isolation.",
            file=sys.stderr,
        )
        return PreparedCommand(
            args=command,
            shell=True,
            env=build_child_env(),
            cwd=workdir,
            preexec_fn=None,
            isolation_level=self.isolation_level,
            network_enforced=False,
        )


# Global sandbox instance (backend resolved once).
_sandbox: Sandbox | None = None


def get_sandbox() -> Sandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = Sandbox()
    return _sandbox
