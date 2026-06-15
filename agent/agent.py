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
    """OpenAI-compatible tool-calling agent with streaming.

    When ``register_final_message_tool()`` is used the model **must** call
    ``final_message`` to signal completion — plain text responses without
    the tool will keep the conversation loop alive.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        max_iterations: int = 15,
        system_prompt: str | None = None,
    ) -> None:
        self.client = OpenAI(base_url=base_url, api_key=api_key)
        self.model = model
        self._tools: list[Tool] = []
        self._final_tool_name: str | None = None
        self._max_iterations = max_iterations
        self.system_prompt = system_prompt

    # ------------------------------------------------------------------
    # Tool registration
    # ------------------------------------------------------------------

    def register_tool(self, tool: Tool) -> None:
        self._tools.append(tool)

    def register_final_message_tool(self) -> None:
        """Register a no-input ``final_message`` tool the model **must** call
        to signal that it is done.

        Until the model calls this tool the agent keeps looping — plain
        text responses or other tool calls will not end the conversation.

        The tool call is handled internally: no ``tool_call`` /
        ``tool_output`` events are yielded and the caller only sees a
        ``done`` event.
        """
        self._final_tool_name = "final_message"
        self._tools.append(
            Tool(
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
        )

    # ------------------------------------------------------------------
    # Streaming loop
    # ------------------------------------------------------------------

    def stream(self, messages: list[dict]) -> Generator[dict, None, None]:
        """Yield streaming events until the model calls ``final_message``.

        *messages* is mutated in-place — after the generator completes it
        contains the full conversation history.
        """
        iteration = 0

        # Inject system prompt once at the front if set
        if self.system_prompt and (
            not messages or messages[0].get("role") != "system"
        ):
            messages.insert(0, {"role": "system", "content": self.system_prompt})

        while True:
            iteration += 1
            if iteration > self._max_iterations:
                yield {
                    "type": "error",
                    "content": f"Agent did not call final_message after "
                    f"{self._max_iterations} iterations",
                }
                return

            specs = [t.to_openai_spec() for t in self._tools] if self._tools else None

            collected_content = ""
            collected_tool_calls: dict[int, dict] = {}

            kwargs: dict[str, Any] = dict(
                model=self.model,
                messages=messages,
                stream=True,
                extra_body={"thinking_token_budget": 2000}
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
                tool_call_list: list[dict[str, Any]] = []
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

                # Assistant message with tool_calls (appended before we decide
                # whether to continue or stop so the conversation is coherent)
                assistant_msg: dict[str, Any] = {
                    "role": "assistant",
                    "content": collected_content or None,
                }
                assistant_msg["tool_calls"] = tool_call_list
                messages.append(assistant_msg)

                # --- final_message check (handled internally) ---
                if self._final_tool_name:
                    for tc_spec in tool_call_list:
                        if tc_spec["function"]["name"] == self._final_tool_name:
                            # Dummy tool result so history stays well-formed
                            messages.append(
                                {
                                    "role": "tool",
                                    "tool_call_id": tc_spec["id"],
                                    "content": "",
                                }
                            )
                            messages.append(
                                {"role": "assistant", "content": collected_content}
                            )
                            yield {"type": "done", "content": collected_content}
                            return

                # --- Execute real tools ---
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

                    tool_obj = next(
                        (t for t in self._tools if t.name == tname), None
                    )
                    if tool_obj:
                        try:
                            result = tool_obj.run(**targs)
                        except Exception as e:
                            result = f"Error executing {tname}: {e}"
                    else:
                        result = f"Error: Tool '{tname}' not found"

                    result_str = str(result)
                    if len(result_str) > 5_000:
                        result_str = result_str[:5_000] + "\n...[truncated]"
                    yield {
                        "type": "tool_output",
                        "name": tname,
                        "content": result_str,
                    }

                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc_spec["id"],
                            "content": result_str,
                        }
                    )

                continue  # Loop back — model can call more tools or final_message

            # --- No tool calls ---
            if self._final_tool_name:
                # final_message is expected but wasn't called — keep the
                # conversation loop alive so the model gets another chance
                messages.append(
                    {"role": "assistant", "content": collected_content}
                )
                continue  # Loop back

            # No final_message tool registered — normal end
            messages.append({"role": "assistant", "content": collected_content})
            yield {"type": "done", "content": collected_content}
            break
