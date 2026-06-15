from markitdown import MarkItDown
from typing import Any, Callable, Generator, get_type_hints
import inspect
import requests


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
    try:
        jina_ai_url = "https://r.jina.ai/"
        response = requests.get(jina_ai_url + url)
        response.raise_for_status()
        return response.text
    except Exception as e:
        md = MarkItDown()
        return md.convert(url).text_content

FETCH_WEBPAGE_TOOL = fetch_webpage  # @tool already makes it a Tool instance


# ---------------------------------------------------------------------------
# Shell tool (streamable)
# ---------------------------------------------------------------------------

import time
import uuid as _uuid
from .shell import get_shell_manager


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
