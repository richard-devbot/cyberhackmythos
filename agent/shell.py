"""Shell manager for running interactive subprocesses with streaming output."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .sandbox import Sandbox, get_sandbox

IDLE_TIMEOUT_SECONDS = 15 * 60  # 15 minutes


@dataclass
class ShellSession:
    """A running shell session."""

    session_id: str
    process: subprocess.Popen[str]
    temp_dir: Path
    output_buffer: list[str] = field(default_factory=list)
    last_read_pos: int = 0
    started_at: float = field(default_factory=time.time)
    last_used_at: float = field(default_factory=time.time)
    closed: bool = False

    @property
    def pid(self) -> int | None:
        return self.process.pid

    @property
    def returncode(self) -> int | None:
        return self.process.returncode

    def touch(self) -> None:
        """Update last_used_at to current time."""
        self.last_used_at = time.time()

    def read_new_output(self) -> str:
        """Read new output since last read."""
        self.touch()
        new_lines = self.output_buffer[self.last_read_pos :]
        self.last_read_pos = len(self.output_buffer)
        return "".join(new_lines)

    def get_full_output(self) -> str:
        """Get all output."""
        self.touch()
        return "".join(self.output_buffer)

    def is_running(self) -> bool:
        """Check if process is still running."""
        return self.process.poll() is None

    def is_idle_expired(self) -> bool:
        """Check if session has been idle longer than IDLE_TIMEOUT_SECONDS."""
        return (time.time() - self.last_used_at) > IDLE_TIMEOUT_SECONDS

    def close(self) -> None:
        """Close the session and clean up temp directory."""
        if not self.closed:
            self.closed = True
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            # Clean up temp directory (retry a few times for Windows file locks)
            if self.temp_dir.exists():
                for _ in range(3):
                    try:
                        shutil.rmtree(self.temp_dir, ignore_errors=False)
                        break
                    except Exception:
                        time.sleep(0.1)


class ShellManager:
    """Manages multiple shell sessions with streaming output."""

    def __init__(self, default_timeout: float = 15.0, sandbox: Sandbox | None = None) -> None:
        self.sessions: dict[str, ShellSession] = {}
        self._lock = threading.Lock()
        self.default_timeout = default_timeout
        self.sandbox = sandbox or get_sandbox()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True
        )
        self._cleanup_thread.start()

    def _cleanup_loop(self) -> None:
        """Background thread that cleans up idle sessions every 60 seconds."""
        while True:
            time.sleep(60)
            self._cleanup_idle_sessions()

    def _cleanup_idle_sessions(self) -> None:
        """Close sessions that have been idle for more than IDLE_TIMEOUT_SECONDS."""
        with self._lock:
            idle_sessions = [
                sid
                for sid, session in self.sessions.items()
                if session.is_idle_expired()
            ]
            for sid in idle_sessions:
                session = self.sessions.pop(sid, None)
                if session:
                    session.close()

    def start(
        self,
        session_id: str,
        command: str,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ShellSession:
        """Start a new shell session in a fresh temp directory."""
        with self._lock:
            # Close existing session with same ID
            if session_id in self.sessions:
                self.sessions[session_id].close()

            # Create a unique temp directory for this session
            temp_dir = Path(tempfile.mkdtemp(prefix=f"shell_{session_id}_"))

            # Resolve the command through the sandbox. This scrubs the environment
            # to an allowlist (so secrets like OPENAI_API_KEY are never visible to
            # the command), applies resource limits, and — on the docker backend —
            # blocks network egress and drops privileges. Any caller-supplied env
            # is passed as explicit non-secret extras.
            prepared = self.sandbox.prepare(command, str(temp_dir))
            child_env = dict(prepared.env)
            if env:
                child_env.update(env)

            process = subprocess.Popen(
                prepared.args,
                shell=prepared.shell,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=prepared.cwd,
                env=child_env,
                preexec_fn=prepared.preexec_fn,
            )

            session = ShellSession(
                session_id=session_id,
                process=process,
                temp_dir=temp_dir,
            )
            self.sessions[session_id] = session

            # Start output reader thread
            thread = threading.Thread(
                target=self._read_output, args=(session,), daemon=True
            )
            thread.start()

            return session

    def _read_output(self, session: ShellSession) -> None:
        """Read output from process in background thread."""
        assert session.process.stdout is not None
        try:
            for line in session.process.stdout:
                with self._lock:
                    session.output_buffer.append(line)
        except Exception:
            pass
        finally:
            with self._lock:
                session.closed = True

    def send_input(self, session_id: str, input_text: str) -> bool:
        """Send input to a running session."""
        with self._lock:
            session = self.sessions.get(session_id)
            if session is None or not session.is_running():
                return False
            if session.process.stdin is None:
                return False
            try:
                session.process.stdin.write(input_text + "\n")
                session.process.stdin.flush()
                session.touch()
                return True
            except Exception:
                return False

    def get_output(self, session_id: str) -> str | None:
        """Get full output from a session."""
        with self._lock:
            session = self.sessions.get(session_id)
            if session is None:
                return None
            return session.get_full_output()

    def poll_output(self, session_id: str) -> str | None:
        """Get new output since last poll."""
        with self._lock:
            session = self.sessions.get(session_id)
            if session is None:
                return None
            return session.read_new_output()

    def is_running(self, session_id: str) -> bool:
        """Check if a session is still running."""
        with self._lock:
            session = self.sessions.get(session_id)
            if session is None:
                return False
            return session.is_running()

    def close(self, session_id: str) -> None:
        """Close a session."""
        with self._lock:
            session = self.sessions.get(session_id)
            if session:
                session.close()

    def close_all(self) -> None:
        """Close all sessions."""
        with self._lock:
            for session in self.sessions.values():
                session.close()
            self.sessions.clear()


# Global shell manager instance
_shell_manager: ShellManager | None = None


def get_shell_manager() -> ShellManager:
    """Get or create the global shell manager."""
    global _shell_manager
    if _shell_manager is None:
        _shell_manager = ShellManager()
    return _shell_manager
