"""Per-process analysis workspace.

Scanners operate on files, so the agent needs a place to put the code under
review. This module owns that directory and enforces that every write stays
inside it (no path traversal) and is readable by a sandboxed, non-root scanner
process (the target code is untrusted *input*, never a secret).
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

_WORKSPACE: Path | None = None


def get_workspace() -> Path:
    """Return (creating on first use) the analysis workspace directory."""
    global _WORKSPACE
    if _WORKSPACE is None:
        _WORKSPACE = Path(tempfile.mkdtemp(prefix="cyberhackmythos_ws_"))
        # World-readable/executable so a sandboxed non-root scanner can read the
        # mounted tree. Contains only the untrusted code under analysis.
        os.chmod(_WORKSPACE, 0o755)
    return _WORKSPACE


def set_workspace(path: str | Path) -> Path:
    """Point the workspace at an existing directory (used by the CLI / tests)."""
    global _WORKSPACE
    _WORKSPACE = Path(path)
    return _WORKSPACE


def resolve_in_workspace(relpath: str) -> Path:
    """Resolve *relpath* under the workspace, rejecting traversal outside it."""
    ws = get_workspace().resolve()
    target = (ws / relpath).resolve()
    if target != ws and ws not in target.parents:
        raise ValueError(f"path '{relpath}' escapes the workspace")
    return target


def write_file(relpath: str, content: str) -> str:
    """Write *content* to *relpath* inside the workspace. Returns the abs path."""
    target = resolve_in_workspace(relpath)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    os.chmod(target, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    return str(target)
