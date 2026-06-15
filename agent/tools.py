from markitdown import MarkItDown
from typing import Any, Callable, get_type_hints
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
        self, name: str, description: str, parameters: dict, handler: Callable[..., str]
    ) -> None:
        self.name = name
        self.description = description
        self.parameters = parameters
        self.handler = handler

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
