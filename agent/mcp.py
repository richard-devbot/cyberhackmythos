"""MCP (Model Context Protocol) client for remote tool servers.

Supports Streamable HTTP transport (JSON-RPC 2.0 over HTTP).
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx

from .tools import Tool


# ---------------------------------------------------------------------------
# MCP Client
# ---------------------------------------------------------------------------


class MCPClient:
    """Connect to a remote MCP server via Streamable HTTP transport."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.url = url
        self.headers = headers or {}
        self.timeout = timeout
        self._session_id: str | None = None
        self._initialized = False

    # ------------------------------------------------------------------
    # Low-level JSON-RPC
    # ------------------------------------------------------------------

    def _request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Send a JSON-RPC request and return the result."""
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self.headers,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(self.url, json=payload, headers=headers)

            # Capture session ID from response
            sid = resp.headers.get("mcp-session-id")
            if sid:
                self._session_id = sid

            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")

            # Handle SSE response
            if "text/event-stream" in content_type:
                return self._parse_sse_response(resp.text)

            # Handle JSON response
            data = resp.json()
            if "error" in data:
                raise RuntimeError(f"MCP error: {data['error']}")
            return data.get("result")

    def _parse_sse_response(self, text: str) -> Any:
        """Parse SSE response text, extracting JSON-RPC results."""
        result = None
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("data:"):
                data_str = line[len("data:") :].strip()
                if data_str:
                    try:
                        data = json.loads(data_str)
                        if "result" in data:
                            result = data["result"]
                        elif "error" in data:
                            raise RuntimeError(f"MCP error: {data['error']}")
                    except json.JSONDecodeError:
                        continue
        return result

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def initialize(self) -> dict[str, Any]:
        """Initialize the MCP session."""
        result = self._request(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "mythos-agent", "version": "0.1.0"},
            },
        )
        self._initialized = True
        # Send initialized notification (no response expected)
        self._notify("notifications/initialized", {})
        return result or {}

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self.headers,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        with httpx.Client(timeout=self.timeout) as client:
            client.post(self.url, json=payload, headers=headers)

    # ------------------------------------------------------------------
    # Tool discovery
    # ------------------------------------------------------------------

    def list_tools(self) -> list[dict[str, Any]]:
        """List available tools from the server."""
        if not self._initialized:
            self.initialize()
        result = self._request("tools/list", {})
        return (result or {}).get("tools", [])

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Call a tool on the server."""
        if not self._initialized:
            self.initialize()
        return self._request("tools/call", {"name": name, "arguments": arguments})


# ---------------------------------------------------------------------------
# MCP Tool wrapper
# ---------------------------------------------------------------------------


def _json_schema_type_to_python(type_str: str) -> type:
    """Map JSON Schema type to Python type."""
    mapping = {"string": str, "integer": int, "number": float, "boolean": bool, "array": list, "object": dict}
    return mapping.get(type_str, str)


def mcp_tool(client: MCPClient, mcp_tool_def: dict[str, Any]) -> Tool:
    """Wrap an MCP tool definition as a local Tool instance.

    Args:
        client: Connected MCPClient.
        mcp_tool_def: Tool dict from ``tools/list`` response.
    """
    name = mcp_tool_def["name"]
    description = mcp_tool_def.get("description", "")
    input_schema = mcp_tool_def.get("inputSchema", {})

    # Convert inputSchema to OpenAI-style parameters
    properties: dict[str, dict] = {}
    for param_name, param_def in input_schema.get("properties", {}).items():
        prop: dict[str, Any] = {"type": param_def.get("type", "string")}
        if "description" in param_def:
            prop["description"] = param_def["description"]
        if "enum" in param_def:
            prop["enum"] = param_def["enum"]
        properties[param_name] = prop

    required = input_schema.get("required", [])

    parameters = {
        "type": "object",
        "properties": properties,
        "required": required,
    }

    def handler(**kwargs: Any) -> str:
        result = client.call_tool(name, kwargs)
        # Extract text content from MCP result
        if isinstance(result, dict) and "content" in result:
            parts = []
            for block in result["content"]:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
            return "\n".join(parts) if parts else json.dumps(result)
        return json.dumps(result) if not isinstance(result, str) else result

    return Tool(name=name, description=description, parameters=parameters, handler=handler)


# ---------------------------------------------------------------------------
# Convenience: connect and load all tools
# ---------------------------------------------------------------------------


def load_mcp_tools(url: str, headers: dict[str, str] | None = None) -> list[Tool]:
    """Connect to an MCP server and return all its tools as Tool instances."""
    client = MCPClient(url=url, headers=headers)
    client.initialize()
    tools_defs = client.list_tools()
    return [mcp_tool(client, td) for td in tools_defs]


# ---------------------------------------------------------------------------
# Pre-configured MCP servers
# ---------------------------------------------------------------------------

MCP_SERVERS: dict[str, dict[str, Any]] = {
    "exa": {
        "url": "https://mcp.exa.ai/mcp",
        "description": "Web search via Exa",
    },
    "context7": {
        "url": "https://mcp.context7.com/mcp",
        "description": "Library documentation lookup",
    },
    "grep_app": {
        "url": "https://mcp.grep.app",
        "description": "GitHub code search via grep.app",
    },
    "github": {
        "url": "https://gitmcp.io/docs",
        "description": "GitHub code search and repository info",
    },
}


def load_all_mcp_tools(
    servers: dict[str, dict[str, Any]] | None = None,
) -> dict[str, list[Tool]]:
    """Load tools from all configured MCP servers.

    Returns:
        ``{server_name: [Tool, ...]}``
    """
    if servers is None:
        servers = MCP_SERVERS

    result: dict[str, list[Tool]] = {}
    for name, cfg in servers.items():
        try:
            result[name] = load_mcp_tools(
                url=cfg["url"],
                headers=cfg.get("headers"),
            )
        except Exception as e:
            print(f"[MCP] Failed to load {name}: {e}")
            result[name] = []
    return result
