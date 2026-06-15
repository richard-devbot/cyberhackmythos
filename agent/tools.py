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
    command: str,
    session_id: str = "",
    input_text: str = "",
    timeout: float = 15.0,
) -> Generator[str, None, None]:
    """Run a shell command with streaming output.

    command (required): The shell command to execute
    session_id: Session ID to send input to (omit to auto-generate)
    input_text: Text to send to running session's stdin
    timeout: Seconds between output updates (default 15)
    """
    manager = get_shell_manager()

    # Check if session_id refers to an existing session
    existing_session = session_id and session_id in manager.sessions

    # If session exists and has input, send it
    if existing_session and input_text:
        sent = manager.send_input(session_id, input_text)
        if not sent:
            yield f"Error: Session '{session_id}' closed or cannot accept input"
            return
        time.sleep(0.5)
        output = manager.poll_output(session_id)
        if output:
            yield f"Sent input. New output:\n{output}"
        else:
            yield "Input sent (no new output yet)"
        return

    # If session exists without input, return current output
    if existing_session:
        output = manager.get_output(session_id)
        if output is None:
            yield f"Error: Session '{session_id}' not found"
            return
        running = manager.is_running(session_id)
        status = "running" if running else f"exited (code {manager.sessions[session_id].returncode})"
        yield f"Session {session_id} [{status}]:\n{output}"
        return

    # Start new command (with provided session_id or auto-generated)
    sid = session_id or str(_uuid.uuid4())[:8]
    session = manager.start(sid, command)
    yield f"Started session {sid} (PID {session.pid})"

    # Stream output — poll frequently, yield when there's new output
    last_yield = time.time()
    while session.is_running():
        time.sleep(0.5)
        output = session.read_new_output()
        if output:
            print(f"Debug: New output for session {sid}:\n{output}")
            yield f"[{sid}] Output:\n{output}"
            last_yield = time.time()

    # Final output
    time.sleep(0.2)
    final = session.read_new_output()
    code = session.process.returncode
    status = f"exited with code {code}" if code is not None else "exited"
    if final:
        yield f"[{sid}] Final ({status}):\n{final}"
    else:
        yield f"[{sid}] {status}"


SHELL_TOOL = Tool(
    name="shell",
    description="Run shell commands with streaming output. Supports interactive sessions — send input to running commands.",
    parameters={
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The shell command to execute",
            },
            "session_id": {
                "type": "string",
                "description": "Session ID to send input to or get output from (omit to start new command)",
            },
            "input_text": {
                "type": "string",
                "description": "Text to send to running session's stdin",
            },
            "timeout": {
                "type": "number",
                "description": "Seconds between output updates (default 15)",
            },
        },
        "required": ["command"],
    },
    handler=_shell_handler,
    streamable=True,
)
