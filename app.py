import html
import time
import uuid
import gradio as gr
from dotenv import load_dotenv
from agent import Agent, FETCH_WEBPAGE_TOOL, SHELL_TOOL, READ_TOOL, FINAL_MESSAGE_TOOL
from agent import config
from agent.sandbox import get_sandbox
from agent.scanners import build_scanner_tools
from agent.intel_tools import build_intel_tools
from agent.remediation import build_remediation_tools
import os
from pathlib import Path

load_dotenv()
gr.set_static_paths("static/")

_SYSTEM_PROMPT = """\
You are cyberhackmythos, an AI agent specialized in defensive cybersecurity code auditing.

=== Evidence over guesses ===
You have REAL security scanners available as tools. Prefer them over eyeballing code —
they produce verifiable, normalized findings (with CWE/CVE/severity):
  - write_file(path, content): stage a pasted codebase into the analysis workspace.
  - scan_all(target='.'): run every scanner (SAST, secrets, dependencies, IaC, container)
    and get merged, deduplicated, severity-ranked findings. This is your default first move.
  - scan_semgrep / scan_bandit / scan_gitleaks / scan_trivy / scan_hadolint: run one scanner.
  - shell(command): explore the workspace (grep, cat, ls) inside a locked-down sandbox.
  - export_sarif(): write all findings to a SARIF report.
  - fetch_webpage(url): look up advisories/CVE details (SSRF-guarded).

=== Recommended workflow ===
1. If the user pasted code, write each file into the workspace with write_file.
2. Run scan_all to get the evidence base.
3. Run enrich_findings to attach EPSS (exploitation probability), CISA KEV (known-exploited),
   and CVSS to CVE findings, and get a transparent priority (act_now / attend / track).
4. For each real finding, explain the vulnerability, its impact, the CWE/CVE, and a
   concrete hotfix patch as a unified diff. Ground every claim in a scanner finding or code you read.
5. VERIFY every patch with verify_patch before presenting it as a fix — it applies the
   diff to an isolated copy, re-scans, and confirms the finding is gone with no regressions.
   Never present an unverified patch as "fixed"; if verify_patch fails, revise and retry.
6. Use threat_report / risk_graph to prioritize; lead with act_now / KEV items.
7. Call export_sarif if a report is useful. Note anything the scanners could not cover.

Do not fabricate findings that no scanner or code inspection supports. If a scanner is
unavailable, say so plainly rather than guessing.

Don't loop endlessly — when you have delivered the analysis and patches, call `final_message`.

=== IMPORTANT: How to end the conversation ===
You MUST call the `final_message` tool when you have completed your response and want to end.
If you do NOT call `final_message`, you will be stuck in a loop:
  - You respond → system waits for final_message → you did not call it
  - → system sends your response back to you → you must respond again
  - → this repeats until you call `final_message`
To break out of the loop, simply call `final_message` with no arguments.
Only call `final_message` when you are done or already responded or stuck in a loop.
"""

def _env_float(name: str) -> float | None:
    v = os.getenv(name)
    return float(v) if v not in (None, "") else None


def _env_int(name: str) -> int | None:
    v = os.getenv(name)
    return int(v) if v not in (None, "") else None


agent = Agent(
    base_url=os.getenv("OPENAI_BASE_URL"),
    api_key=os.getenv("OPENAI_API_KEY"),
    model=os.getenv("OPENAI_MODEL"),
    system_prompt=_SYSTEM_PROMPT,
    max_iterations=config.MAX_ITERATIONS,
    temperature=_env_float("OPENAI_TEMPERATURE"),
    top_p=_env_float("OPENAI_TOP_P"),
    max_tokens=_env_int("OPENAI_MAX_TOKENS"),
    thinking_token_budget=_env_int("THINKING_TOKEN_BUDGET"),
)

# Surface the active isolation tier at startup so operators know what protection
# is actually in force (transparency: never imply isolation we don't have).
print(f"[cyberhackmythos] {get_sandbox().describe()}")
agent.register_tool(FETCH_WEBPAGE_TOOL, SHELL_TOOL, READ_TOOL, FINAL_MESSAGE_TOOL)
# Real security scanners (SAST, secrets, dependencies, IaC, container) exposed as
# sandboxed tools that emit normalized findings — see agent/scanners/.
agent.register_tool(*build_scanner_tools())
# Threat intelligence: enrich CVE findings with EPSS / CISA KEV / CVSS + priority,
# threat report, and risk graph — see agent/intel.py.
agent.register_tool(*build_intel_tools())
# Verified remediation: apply a patch in an isolated copy, re-scan to prove the
# finding is gone, and check for regressions — see agent/remediation.py.
agent.register_tool(*build_remediation_tools())
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
                        "content": f'<span style="color: var(--color-red-500)">{html.escape(str(ev["content"]))}</span>',
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
                "content": f'<span style="color: var(--color-red-400)">{html.escape(str(exc))}</span>',
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

with gr.Blocks(fill_width=True, title="cyberhackmythos") as demo:
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
                            <img src="/gradio_api/file=static/svg/logo.svg" alt="cyberhackmythos" width="420" height="70" />
                        </div>
                    </div>
                    <div class="landing-prompt">
                        <p>AI security auditing — real scanners, live threat intel, verified patches</p>
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
                autoscroll=True
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
    # Auth is enabled when CYBERHACKMYTHOS_APP_AUTH is set ("user:pass,..."). A tool
    # that can run shell commands should never be exposed unauthenticated on a
    # shared host — leaving this unset is only appropriate for localhost.
    _auth = config.APP_AUTH or None
    if _auth is None:
        print("[cyberhackmythos] WARNING: no app auth configured (set CYBERHACKMYTHOS_APP_AUTH for shared deployments)")
    demo.queue(default_concurrency_limit=100, max_size=100).launch(
        ssr_mode=False,
        max_threads=100,
        css_paths="app.css",
        theme=theme,
        auth=_auth,
    )