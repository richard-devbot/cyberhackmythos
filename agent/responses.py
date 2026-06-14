"""
Streaming event types yielded by Agent.stream().

Each event is a plain dict with at least a ``"type"`` key.
"""

# ── Text chunk ──────────────────────────────────────────────────────────
# {"type": "text",      "content": "partial assistant message"}
TEXT = "text"

# ── Reasoning (e.g. DeepSeek R1 chain-of-thought) ──────────────────────
# {"type": "reasoning", "content": "model thinking"}
REASONING = "reasoning"

# ── Tool was called by the model ────────────────────────────────────────
# {"type": "tool_call",   "name": "fetch_webpage", "arguments": '{"url":"..."}'}
TOOL_CALL = "tool_call"

# ── Tool execution output ───────────────────────────────────────────────
# {"type": "tool_output", "name": "fetch_webpage", "content": "<html>..."}
TOOL_OUTPUT = "tool_output"

# ── Final response (no more tool calls) ─────────────────────────────────
# {"type": "done",       "content": "full assistant message"}
DONE = "done"

# ── Fatal error ─────────────────────────────────────────────────────────
# {"type": "error",      "content": "API key invalid"}
ERROR = "error"
