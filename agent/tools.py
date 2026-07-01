from typing import Any, Callable, Generator, get_type_hints
from collections import OrderedDict
import inspect
import time
import uuid as _uuid

from . import config
from .netguard import safe_fetch, validate_public_url, UrlNotAllowed
from .shell import get_shell_manager


def python_type_to_json_schema(tp: type) -> str:
    """Map a Python type to a JSON Schema type string."""
    mapping = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object",
    }
    return mapping.get(tp, "string")

class Tool:
    """A callable tool the agent can invoke."""

    def __init__(
        self,
        name: str,
        description: str,
        parameters: dict,
        handler: Callable[..., str],
        streamable: bool = False,
    ) -> None:
        self.name = name
        self.description = description
        self.parameters = parameters
        self.handler = handler
        self.streamable = streamable

    def to_openai_spec(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def run(self, **kwargs: Any) -> str:
        return self.handler(**kwargs)

    def stream(self, **kwargs: Any) -> Generator[str, None, None]:
        """Yield partial results for streamable tools.

        Override in subclasses or use streamable=True with a generator handler.
        """
        if self.streamable and callable(self.handler):
            result = self.handler(**kwargs)
            if isinstance(result, Generator):
                yield from result
            else:
                yield str(result)
        else:
            yield self.handler(**kwargs)


def _parse_docstring(docstring: str) -> tuple[str, dict[str, tuple[bool, str]]]:
    """Parse a tool docstring into description and param metadata.

    Returns:
        (description, {param_name: (required, description)})

    Expected format:
        First line: tool description.
        Subsequent lines: ``param_name (required): description`` or
        ``param_name: description``.
    """
    lines = (docstring or "").strip().split("\n")
    description = lines[0].strip()
    param_info: dict[str, tuple[bool, str]] = {}

    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        # Match: param_name (required): description
        #    or: param_name: description
        if ":" not in line:
            continue
        key, desc = line.split(":", 1)
        key = key.strip()
        desc = desc.strip()
        required = False
        if key.endswith("(required)"):
            required = True
            key = key[: -len("(required)")].strip()
        if key:
            param_info[key] = (required, desc)

    return description, param_info


def tool(fn: Callable[..., str]) -> Tool:
    """Decorator that converts a function into a Tool instance.

    Extracts name, description (first line of docstring), and parameters
    from the function's type hints and signature.

    Docstring format:
        First line: tool description.
        Subsequent lines: ``param_name (required): description`` or
        ``param_name: description``.
    """
    name = fn.__name__
    docstring = fn.__doc__ or ""
    description, param_info = _parse_docstring(docstring)

    hints = get_type_hints(fn)
    sig = inspect.signature(fn)

    properties: dict[str, dict] = {}
    required: list[str] = []

    for param_name, param in sig.parameters.items():
        if param_name in hints:
            param_schema: dict[str, Any] = {
                "type": python_type_to_json_schema(hints[param_name])
            }
            # Enrich with docstring info if present
            if param_name in param_info:
                doc_required, doc_desc = param_info[param_name]
                if doc_desc:
                    param_schema["description"] = doc_desc
                # Docstring (required) overrides signature default check
                if doc_required:
                    required.append(param_name)
                elif param.default is inspect.Parameter.empty:
                    required.append(param_name)
            elif param.default is inspect.Parameter.empty:
                required.append(param_name)
            properties[param_name] = param_schema

    parameters = {
        "type": "object",
        "properties": properties,
        "required": required,
    }

    return Tool(
        name=name,
        description=description,
        parameters=parameters,
        handler=fn,
    )


@tool
def fetch_webpage(url: str) -> str:
    """Fetch a webpage and return its text content.

    url (required): The URL to fetch
    """
    # SSRF guard: refuse internal / loopback / link-local (cloud metadata) targets
    # before any network call, in-process or via a third-party reader.
    try:
        validate_public_url(url)
    except UrlNotAllowed as exc:
        return f"Error: URL blocked by SSRF guard: {exc}"

    # Optional third-party reader (off by default — it leaks target URLs to jina).
    # The inner URL was already validated as public above.
    if config.FETCH_USE_JINA:
        try:
            return safe_fetch("https://r.jina.ai/" + url)
        except Exception:
            pass

    try:
        return safe_fetch(url)
    except Exception as exc:
        return f"Error fetching {url}: {exc}"

FETCH_WEBPAGE_TOOL = fetch_webpage  # @tool already makes it a Tool instance


# ---------------------------------------------------------------------------
# Shell tool (streamable)
# ---------------------------------------------------------------------------


def _shell_handler(
    command: str = "",
    session_id: str = "",
    input_text: str = "",
) -> str:
    """Run shell commands interactively with persistent sessions.

    command: The shell command to execute (omit when checking output or sending input)
    session_id: Session ID to check output or send input to (omit to start new command)
    input_text: Text to send to running session's stdin

    How it works:
    - Start new command: provide command, returns session_id immediately (non-blocking)
    - Check output: provide session_id only, returns current output
    - Send input: provide session_id + input_text
    - Sessions auto-destroy after 15 min idle
    - Each session runs in its own temp folder (also cleaned up on timeout)
    - Environment variables persist across calls in the same session
    """
    manager = get_shell_manager()

    existing_session = session_id and session_id in manager.sessions

    # Send input to running session
    if existing_session and input_text:
        sent = manager.send_input(session_id, input_text)
        if not sent:
            return f"Error: Session '{session_id}' closed or not found"
        time.sleep(0.3)
        output = manager.poll_output(session_id)
        running = manager.is_running(session_id)
        status = "running" if running else f"exited (code {manager.sessions[session_id].returncode})"
        if output:
            return f"[{session_id}] {status}:\n{output}"
        return f"[{session_id}] {status} (no new output)"

    # Check output of existing session
    if existing_session:
        output = manager.get_output(session_id)
        running = manager.is_running(session_id)
        code = manager.sessions[session_id].returncode
        status = "running" if running else f"exited with code {code}"
        if output:
            return f"[{session_id}] {status}:\n{output}"
        return f"[{session_id}] {status}"

    # Need a command to start a new session
    if not command.strip():
        if session_id:
            return f"Error: Session '{session_id}' not found or expired"
        return "Error: Provide a command to start a new session, or a session_id to check status"

    # Start new command
    sid = session_id or str(_uuid.uuid4())[:8]
    session = manager.start(sid, command)

    # Wait a bit to capture initial output (fast commands finish here)
    time.sleep(0.5)
    initial = session.read_new_output()
    running = session.is_running()

    if not running:
        # Command finished quickly
        code = session.process.returncode
        final = session.read_new_output()
        output = (initial + final).strip()
        if output:
            return f"[{sid}] exited with code {code}:\n{output}"
        return f"[{sid}] exited with code {code}"

    # Command still running — return status so model can check later
    if initial:
        return f"[{sid}] running (PID {session.pid}):\n{initial}\n\nCall again with session_id=\"{sid}\" to check output."
    return f"[{sid}] running (PID {session.pid})\n\nCall again with session_id=\"{sid}\" to check output."


SHELL_TOOL = Tool(
    name="shell",
    description="Run shell commands with persistent sessions. Start command -> get session_id. Call with session_id to check output or send input. Sessions auto-destroy after 15 min idle. Each session has its own temp folder.",
    parameters={
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Shell command to execute (omit when checking output or sending input)",
            },
            "session_id": {
                "type": "string",
                "description": "Session ID to check output or send input (omit to start new command)",
            },
            "input_text": {
                "type": "string",
                "description": "Text to send to running session's stdin",
            },
        },
        "required": [],
    },
    handler=_shell_handler,
    streamable=False,
)


# Shared cache for read_tool_response - agent writes, tool reads.
# LRU-bounded so it cannot grow without limit across sessions.
class _BoundedCache(OrderedDict):
    """Dict with LRU eviction once it exceeds ``maxsize`` entries."""

    def __init__(self, maxsize: int) -> None:
        super().__init__()
        self._maxsize = max(1, maxsize)

    def __setitem__(self, key: str, value: str) -> None:
        if key in self:
            super().__delitem__(key)
        super().__setitem__(key, value)
        while len(self) > self._maxsize:
            self.popitem(last=False)


_TOOL_RESULTS_CACHE: "OrderedDict[str, str]" = _BoundedCache(config.TOOL_CACHE_MAX_ENTRIES)


def _read_tool_handler(tool_call_id: str, start_line: int, num_lines: int = 50) -> str:
    """Read more lines from a truncated tool response.

    tool_call_id (required): The tool_call_id from the truncated response
    start_line (required): Line number to start reading from
    num_lines: Number of lines to read (default 50)
    """
    full = _TOOL_RESULTS_CACHE.get(tool_call_id)
    if full is None:
        return f"Error: No result found for tool_call_id '{tool_call_id}'"
    lines = full.split("\n")
    total = len(lines)
    if start_line >= total:
        return f"Error: start_line {start_line} >= total lines {total}"
    end = min(start_line + num_lines, total)
    chunk = "\n".join(lines[start_line:end])
    remaining = total - end
    header = f"Lines {start_line}-{end} of {total}"
    if remaining > 0:
        header += f" ({remaining} lines remaining)"
    return f"{header}\n\n{chunk}"


READ_TOOL = Tool(
    name="read_tool_response",
    description="Read more lines from a truncated tool response. Use when a previous tool output was truncated.",
    parameters={
        "type": "object",
        "properties": {
            "tool_call_id": {
                "type": "string",
                "description": "The tool_call_id from the truncated response",
            },
            "start_line": {
                "type": "integer",
                "description": "Line number to start reading from (0-indexed)",
            },
            "num_lines": {
                "type": "integer",
                "description": "Number of lines to read (default 50)",
            },
        },
        "required": ["tool_call_id", "start_line"],
    },
    handler=_read_tool_handler,
)

FINAL_MESSAGE_TOOL = Tool(
    name="final_message",
    description=(
        "Signal that you have completed your response and want "
        "to end the conversation. Call this ONLY when you are "
        "truly done. Until you call this tool, the conversation "
        "will continue. Means you will multiple times answer the"
        "same question or can get stuck in loops if you never call it."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    handler=lambda: "",
)
