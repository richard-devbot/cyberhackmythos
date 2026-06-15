import time
import uuid
import gradio as gr
from dotenv import load_dotenv
from agent import Agent, FETCH_WEBPAGE_TOOL, SHELL_TOOL, READ_TOOL, FINAL_MESSAGE_TOOL
import os
from pathlib import Path

load_dotenv()
gr.set_static_paths("static/")

_SYSTEM_PROMPT = """\
You are OpenMythos, a powerful AI agent specialized in cybersecurity-related tasks.

You have access to tools that you can use to accomplish your goals.

You are a multi-level vulnerability analysis, a visual dependency risk path, a declared threat level then generates an instant, verifiable hotfix patch before threat actors can exploit it.

=== IMPORTANT: How to end the conversation ===
You MUST call the `final_message` tool when you have completed your response and want to end.
If you do NOT call `final_message`, you will be stuck in a loop:
  - You respond → system waits for final_message → you did not call it
  - → system sends your response back to you → you must respond again
  - → this repeats until you call `final_message`
To break out of the loop, simply call `final_message` with no arguments.
Only call `final_message` when you are done or already responded or stuck in a loop.
"""

agent = Agent(
    base_url=os.getenv("OPENAI_BASE_URL"),
    api_key=os.getenv("OPENAI_API_KEY"),
    model=os.getenv("OPENAI_MODEL"),
    system_prompt=_SYSTEM_PROMPT,
)
agent.register_tool(FETCH_WEBPAGE_TOOL, SHELL_TOOL, READ_TOOL, FINAL_MESSAGE_TOOL)
agent.register_all_mcp()
agent.set_final_message_tool()

# Load JS from external files
_js_dir = Path(__file__).parent / "static" / "js"
JS_LOAD_STATE = (_js_dir / "storage.load.js").read_text()
JS_SAVE_STATE = (_js_dir / "storage.save.js").read_text()
LANDING_PAGE_SCRIPT = (_js_dir / "landing.js").read_text()


def _conv_choices(state_value):
    convs = sorted(state_value["conversations"], key=lambda c: c.get("last_updated", 0), reverse=True)
    return gr.update(
        choices=[(c["label"], c["key"]) for c in convs],
        value=state_value.get("conversation_id") or None,
    )


class GradioEvents:
    """Event handlers for the chatbot UI."""

    @staticmethod
    def stream_response(message, state_value):
        """Stream a chat completion into the active conversation."""
        if not message or not message.strip():
            yield gr.skip()
            return

        if not state_value.get("conversation_id"):
            conv_id = str(uuid.uuid4())
            state_value["conversation_id"] = conv_id
            state_value["conversations"].append(
                {"label": message[:30], "key": conv_id, "last_updated": int(time.time() * 1000)})
            state_value["conversation_contexts"][conv_id] = {
                "history": []
            }
        else:
            conv_id = state_value["conversation_id"]
            state_value["conversation_contexts"].setdefault(
                conv_id, {"history": []})
            # Update last_updated for existing conversation
            for c in state_value["conversations"]:
                if c["key"] == conv_id:
                    c["last_updated"] = int(time.time() * 1000)
                    break

        ctx = state_value["conversation_contexts"][conv_id]

        for c in state_value["conversations"]:
            if c["key"] == conv_id and not c.get("label"):
                c["label"] = message[:30]
                break

        ctx["history"].append({"role": "user", "content": message})

        yield { msg: gr.update(value=""), chatbot: gr.update(value=ctx["history"]), state: gr.update(value=state_value), conv_choice: _conv_choices(state_value), send_btn: gr.update(visible=False), stop_btn: gr.update(visible=True)}

        # Build display as separate titled messages (smolagents style)
        display_messages: list[dict] = list(ctx["history"])
        text_msg_idx: int | None = None
        thinking_msg_idx: int | None = None
        tool_call_idx: int | None = None
        spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spinner_idx = 0

        try:
            for ev in agent.stream(ctx["history"]):
                t = ev["type"]

                if t == "reasoning":
                    spinner_idx += 1
                    content = f"<span class=\"thinking-indicator\">{spinner_frames[spinner_idx % len(spinner_frames)]}  Thinking...</span>"
                    if thinking_msg_idx is not None:
                        display_messages[thinking_msg_idx]["content"] = content
                    else:
                        display_messages.append({"role": "assistant", "content": content, "metadata": {}})
                        thinking_msg_idx = len(display_messages) - 1

                elif t == "text":
                    # Remove spinner message if showing — it was a separate bubble
                    if thinking_msg_idx is not None:
                        display_messages.pop(thinking_msg_idx)
                        thinking_msg_idx = None
                        # Re-index since we popped
                        if text_msg_idx is not None and thinking_msg_idx is not None:
                            if  text_msg_idx > thinking_msg_idx:
                                text_msg_idx -= 1

                    if text_msg_idx is not None:
                        display_messages[text_msg_idx]["content"] += ev["content"]
                    else:
                        display_messages.append({"role": "assistant", "content": ev["content"], "metadata": {}})
                        text_msg_idx = len(display_messages) - 1

                elif t == "tool_call":
                    # Remove spinner if present
                    if thinking_msg_idx is not None:
                        display_messages.pop(thinking_msg_idx)
                        if text_msg_idx is not None and text_msg_idx > thinking_msg_idx:
                            text_msg_idx -= 1
                        thinking_msg_idx = None

                    # Finalize any in-flight text message (keep if it has real content)
                    if text_msg_idx is not None:
                        c = display_messages[text_msg_idx].get("content", "").strip()
                        if not c:
                            display_messages.pop(text_msg_idx)
                        text_msg_idx = None
                    tool_call_idx = None

                    tool_name = ev["name"]
                    display_messages.append({
                        "role": "assistant",
                        "content": f"```\n{tool_name}({ev['arguments']})\n```\n⏳ Running...",
                        "metadata": {"title": f"🛠️ Used tool {tool_name}"},
                    })
                    tool_call_idx = len(display_messages) - 1

                elif t == "tool_output":
                    if tool_call_idx is not None:
                        snippet = ev["content"][:500]
                        cc = snippet if len(ev["content"]) <= 500 else snippet + "\n..."
                        # Grab the tool name from the existing message
                        tool_name = display_messages[tool_call_idx]["metadata"]["title"].split("Used tool ")[-1]
                        display_messages[tool_call_idx]["content"] = (
                            f"```\n{tool_name}({ev['arguments']})\n```\n\n"
                            f"**Output:**\n```\n{cc}\n```"
                        )
                        display_messages[tool_call_idx]["metadata"] = {
                            "title": f"🛠️ {tool_name} — {len(ev['content'])} chars",
                        }
                        # Only clear tool_call_idx if NOT partial (final output)
                        if not ev.get("partial"):
                            tool_call_idx = None

                elif t == "error":
                    display_messages.append({
                        "role": "assistant",
                        "content": f'<span style="color: var(--color-red-500)">{ev["content"]}</span>',
                        "metadata": {"title": "💥 Error"},
                    })
                    yield {
                        chatbot: gr.update(value=display_messages),
                        state: gr.update(value=state_value),
                        send_btn: gr.update(visible=True),
                        stop_btn: gr.update(visible=False),
                    }
                    return

                elif t == "done":
                    break

                # Update history in real-time so state always has latest messages
                ctx["history"] = display_messages

                yield {
                    chatbot: gr.update(value=display_messages),
                    state: gr.update(value=state_value),
                }

            # Final sync (ensures tool output messages are saved)
            ctx["history"] = display_messages

            yield {
                chatbot: gr.update(value=ctx["history"]),
                state: gr.update(value=state_value),
                send_btn: gr.update(visible=True),
                stop_btn: gr.update(visible=False),
            }

        except Exception as exc:
            display_messages.append({
                "role": "assistant",
                "content": f'<span style="color: var(--color-red-400)">{exc}</span>',
                "metadata": {"title": "💥 Error"},
            })
            ctx["history"] = display_messages
            yield {
                chatbot: gr.update(value=display_messages),
                state: gr.update(value=state_value),
                send_btn: gr.update(visible=True),
                stop_btn: gr.update(visible=False),
            }

    @staticmethod
    def new_chat(state_value):
        state_value["conversation_id"] = ""
        return (
            gr.update(value=None),
            gr.update(value=None),
            gr.update(value=state_value),
        )

    @staticmethod
    def select_conversation(choice, state_value):
        if not choice:
            return gr.skip()
        if choice == state_value.get("conversation_id"):
            return gr.skip()

        state_value["conversation_id"] = choice
        ctx = state_value["conversation_contexts"].get(choice, {})
        return (
            gr.update(value=ctx.get("history", [])),
            gr.update(value=state_value),
        )

    @staticmethod
    def delete_selected_conversation(choice, state_value):
        if not choice:
            return gr.skip()

        state_value["conversation_contexts"].pop(choice, None)
        state_value["conversations"] = [
            c for c in state_value["conversations"] if c["key"] != choice
        ]
        was_active = state_value.get("conversation_id") == choice
        if was_active:
            state_value["conversation_id"] = ""
            return (
                _conv_choices(state_value),
                gr.update(value=None),
                gr.update(value=state_value),
            )
        return (
            _conv_choices(state_value),
            gr.skip(),
            gr.update(value=state_value),
        )

    @staticmethod
    def cancel_stream(state_value):
        """Mark the current assistant message as cancelled."""
        if not state_value.get("conversation_id"):
            return gr.skip()
        ctx = state_value["conversation_contexts"][
            state_value["conversation_id"]]
        if ctx.get("history") and ctx["history"][-1].get("role") == "assistant":
            ctx["history"][-1]["metadata"] = ctx["history"][-1].get(
                "metadata", {})
            ctx["history"][-1]["metadata"]["footer"] = "Chat completion paused"
        return (gr.update(value=ctx.get("history", [])), gr.update(value=state_value), gr.update(visible=True), gr.update(visible=False))

    @staticmethod
    def load_from_js(serialised_json, state_value):
        """Receive the JSON string that JS_LOAD_STATE returned, merge into state."""
        import json
        if not serialised_json:
            return gr.skip(), gr.skip()
        try:
            loaded = json.loads(serialised_json)
        except Exception:
            return gr.skip(), gr.skip()

        state_value["conversations"] = loaded.get("conversations", [])
        state_value["conversation_contexts"] = loaded.get("conversation_contexts", {})
        return _conv_choices(state_value), gr.update(value=state_value)

    @staticmethod
    def prepare_save(state_value):
        """Serialise state to JSON so JS_SAVE_STATE can write it to localStorage."""
        import json
        return json.dumps({
            "conversations": state_value.get("conversations", []),
            "conversation_contexts": state_value.get("conversation_contexts", {}),
        })

with gr.Blocks(fill_width=True, title="Demo Chat") as demo:
    state = gr.State({
        "conversation_contexts": {},
        "conversations": [],
        "conversation_id": "",
    })

    js_load_output = gr.Textbox(visible=False, elem_id="js-load-output")
    js_save_input  = gr.Textbox(visible=False, elem_id="js-save-input")

    with gr.Row(elem_id="main-row"):
        with gr.Sidebar(open=False):
            new_chat_btn = gr.Button(
                value="New Conversation",
                variant="primary",
            )
            conv_choice = gr.Radio(
                choices=[],
                label=None,
                interactive=True,
                elem_id="conversations-radio",
            )
            delete_btn = gr.Button(
                value="Delete Selected",
                variant="stop",
                visible=False
            )

        with gr.Column(elem_id="chat-column"):

            # Landing page shown when chat is empty with added hyperlinks
            landing_page = gr.HTML(
                value="""
                <div id="landing-page">
                    <div class="landing-content">
                        <div class="landing-logo">
                            <img src="/gradio_api/file=static/svg/logo.svg" alt="MythosHarness" width="420" height="70" />
                        </div>
                    </div>
                    <div class="landing-prompt">
                        <p>Made with ❤️ by <a href="http://huggingface.co/KingNish" target="_blank" style="color: var(--primary-500, #ff4b4b); text-decoration: underline;">KingNish</a> and <a href="https://huggingface.co/himanshu17HF" target="_blank" style="color: var(--primary-500, #ff4b4b); text-decoration: underline;">Himanshu</a></p>
                    </div>
                </div>
                """,
                elem_id="landing-page-container",
            )

            chatbot = gr.Chatbot(
                elem_id="chatbot",
                show_label=False,
                buttons=[],
                layout="bubble",
                autoscroll=False
            )
            with gr.Row(elem_id="input-row"):
                msg = gr.Textbox(
                    placeholder="Enter your message here...",
                    show_label=False,
                    scale=4,
                    container=False,
                    max_lines=10,
                )
                send_btn = gr.Button(
                    "Send",
                    variant="primary",
                    scale=0,
                    min_width=40,
                    elem_id="send-btn",
                )
                stop_btn = gr.Button(
                    "Stop",
                    variant="stop",
                    scale=0,
                    min_width=40,
                    visible=False,
                    elem_id="stop-btn",
                )

    new_chat_btn.click(
        fn=GradioEvents.new_chat,
        inputs=[state],
        outputs=[conv_choice, chatbot, state],
    )

    conv_choice.change(
        fn=GradioEvents.select_conversation,
        inputs=[conv_choice, state],
        outputs=[chatbot, state],
    )

    delete_btn.click(
        fn=GradioEvents.delete_selected_conversation,
        inputs=[conv_choice, state],
        outputs=[conv_choice, chatbot, state],
    )

    submit_event = send_btn.click(
        fn=GradioEvents.stream_response,
        inputs=[msg, state],
        outputs=[msg, chatbot, state, conv_choice, send_btn, stop_btn],
    )
    msg.submit(
        fn=GradioEvents.stream_response,
        inputs=[msg, state],
        outputs=[msg, chatbot, state, conv_choice, send_btn, stop_btn],
    )

    stop_btn.click(
        fn=GradioEvents.cancel_stream,
        inputs=[state],
        outputs=[chatbot, state, send_btn, stop_btn],
        cancels=[submit_event],
    )

    state.change(
        fn=GradioEvents.prepare_save,
        inputs=[state],
        outputs=[js_save_input],
    ).then(
        fn=lambda x: x,
        inputs=[js_save_input],
        outputs=[js_save_input],
        js=JS_SAVE_STATE,
    )

    demo.load(
        fn=lambda: None,
        inputs=None,
        outputs=None,
        js=LANDING_PAGE_SCRIPT,
    ).then(
        fn=lambda x: x,
        inputs=[js_load_output],
        outputs=[js_load_output],
        js=JS_LOAD_STATE,
    ).then(
        fn=GradioEvents.load_from_js,
        inputs=[js_load_output, state],
        outputs=[conv_choice, state],
    )

theme = gr.themes.Base(radius_size="none")

if __name__ == "__main__":
    demo.queue(default_concurrency_limit=100, max_size=100).launch(ssr_mode=False, max_threads=100, css_paths="app.css", theme=theme)