import json
from typing import Any, Generator

from openai import OpenAI

from .tools import Tool

# ---------------------------------------------------------------------------
# Streaming event contract
# ---------------------------------------------------------------------------
# Each yield from Agent.stream() is a dict with a "type" key:
#
#   {"type": "text",     "content": "partial text"}
#   {"type": "reasoning","content": "model thinking"}
#   {"type": "tool_call", "name": str, "arguments": '{"url":"..."}'}
#   {"type": "tool_output","name": str, "content": "result"}
#   {"type": "done",     "content": "full assistant response"}
#   {"type": "error",    "content": "error message"}
# ---------------------------------------------------------------------------


class Agent:
    """OpenAI-compatible tool-calling agent with streaming."""

    def __init__(self, base_url: str, api_key: str, model: str) -> None:
        self.client = OpenAI(base_url=base_url, api_key=api_key)
        self.model = model
        self._tools: list[Tool] = []

    def register_tool(self, tool: Tool) -> None:
        self._tools.append(tool)

    def stream(self, messages: list[dict]) -> Generator[dict, None, None]:
        """Yield streaming events until the model produces a final response.

        *messages* is mutated in-place — after the generator completes it
        contains the full conversation history (including assistant replies,
        tool calls, and tool outputs).
        """
        while True:
            specs = [t.to_openai_spec() for t in self._tools] if self._tools else None

            collected_content = ""
            collected_tool_calls: dict[int, dict] = {}

            kwargs: dict[str, Any] = dict(
                model=self.model,
                messages=messages,
                stream=True,
            )
            if specs:
                kwargs["tools"] = specs

            try:
                stream = self.client.chat.completions.create(**kwargs)
            except Exception as exc:
                yield {"type": "error", "content": str(exc)}
                return

            for chunk in stream:
                cd = chunk.to_dict()
                choices = cd.get("choices", [])
                if not choices:
                    continue
                delta = choices[0].get("delta", {})

                # Reasoning (e.g. DeepSeek R1)
                reasoning = delta.get("reasoning_content") or delta.get("reasoning")
                if reasoning:
                    yield {"type": "reasoning", "content": reasoning}

                # Text content
                content = delta.get("content", "")
                if content:
                    collected_content += content
                    yield {"type": "text", "content": content}

                # Tool call fragments
                for tc in delta.get("tool_calls", []):
                    idx = tc.get("index", 0)
                    if idx not in collected_tool_calls:
                        collected_tool_calls[idx] = {
                            "id": tc.get("id", ""),
                            "function": {"name": "", "arguments": ""},
                        }
                    if tc.get("id"):
                        collected_tool_calls[idx]["id"] = tc["id"]
                    fn = tc.get("function", {})
                    if fn.get("name"):
                        collected_tool_calls[idx]["function"]["name"] += fn["name"]
                    if fn.get("arguments"):
                        collected_tool_calls[idx]["function"]["arguments"] += fn[
                            "arguments"
                        ]

            # --- Handle tool calls ---
            if collected_tool_calls:
                tool_call_list = []
                for idx in sorted(collected_tool_calls.keys()):
                    tc = collected_tool_calls[idx]
                    tool_call_list.append(
                        {
                            "id": tc["id"],
                            "type": "function",
                            "function": {
                                "name": tc["function"]["name"],
                                "arguments": tc["function"]["arguments"],
                            },
                        }
                    )

                # Assistant message with tool_calls
                assistant_msg: dict[str, Any] = {
                    "role": "assistant",
                    "content": collected_content or None,
                }
                assistant_msg["tool_calls"] = tool_call_list
                messages.append(assistant_msg)

                # Execute each tool and append results
                for tc_spec in tool_call_list:
                    tname = tc_spec["function"]["name"]
                    try:
                        targs = json.loads(tc_spec["function"]["arguments"])
                    except json.JSONDecodeError:
                        targs = {}

                    yield {
                        "type": "tool_call",
                        "name": tname,
                        "arguments": tc_spec["function"]["arguments"],
                    }

                    tool_obj = next((t for t in self._tools if t.name == tname), None)
                    if tool_obj:
                        try:
                            result = tool_obj.run(**targs)
                        except Exception as e:
                            result = f"Error executing {tname}: {e}"
                    else:
                        result = f"Error: Tool '{tname}' not found"

                    result_str = str(result)
                    # if result is too long, truncate and indicate truncation
                    if len(result_str) > 5_000:
                        result_str = result_str[:5_000] + "\n...[truncated]"
                    yield {"type": "tool_output", "name": tname, "content": result_str}

                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc_spec["id"],
                            "content": result_str,
                        }
                    )

                continue  # Loop back so the model can respond after tools

            # --- No tool calls — final response ---
            messages.append({"role": "assistant", "content": collected_content})
            yield {"type": "done", "content": collected_content}
            break
