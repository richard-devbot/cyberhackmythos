"""Shell manager for running interactive subprocesses with streaming output."""

from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import IO


@dataclass
class ShellSession:
    """A running shell session."""

    session_id: str
    process: subprocess.Popen[str]
    output_buffer: list[str] = field(default_factory=list)
    last_read_pos: int = 0
    started_at: float = field(default_factory=time.time)
    closed: bool = False

    @property
    def pid(self) -> int | None:
        return self.process.pid

    @property
    def returncode(self) -> int | None:
        return self.process.returncode

    def read_new_output(self) -> str:
        """Read new output since last read."""
        new_lines = self.output_buffer[self.last_read_pos :]
        self.last_read_pos = len(self.output_buffer)
        return "".join(new_lines)

    def get_full_output(self) -> str:
        """Get all output."""
        return "".join(self.output_buffer)

    def is_running(self) -> bool:
        """Check if process is still running."""
        return self.process.poll() is None

    def close(self) -> None:
        """Close the session."""
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


class ShellManager:
    """Manages multiple shell sessions with streaming output."""

    def __init__(self, default_timeout: float = 15.0) -> None:
        self.sessions: dict[str, ShellSession] = {}
        self._lock = threading.Lock()
        self.default_timeout = default_timeout

    def start(
        self,
        session_id: str,
        command: str,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ShellSession:
        """Start a new shell session."""
        with self._lock:
            # Close existing session with same ID
            if session_id in self.sessions:
                self.sessions[session_id].close()

            # Use shell=True for interactive commands
            process = subprocess.Popen(
                command,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=cwd,
                env=env,
            )

            session = ShellSession(session_id=session_id, process=process)
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
