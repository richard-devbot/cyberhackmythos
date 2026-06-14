import time
import uuid
import gradio as gr
from openai import OpenAI
from dotenv import load_dotenv
import os
from pathlib import Path

load_dotenv()
gr.set_static_paths("static/")

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
    base_url=os.getenv("OPENAI_BASE_URL"),
)
model = os.getenv("OPENAI_MODEL")

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

        normal_content = ""
        is_reasoning = False
        spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spinner_idx = 0
        temp = []

        try:
            stream = client.chat.completions.create(
                model=model,
                messages=ctx["history"],
                stream=True
            )

            for chunk in stream:
                chunk = chunk.to_dict()
                delta = chunk['choices'][0]['delta']

                if delta.get('reasoning_content') or delta.get('reasoning'):
                    if not is_reasoning:
                        is_reasoning = True
                    spinner_idx += 1
                    temp = [{
                        "role": "assistant",
                        "content": f"<span class=\"thinking-indicator\">{spinner_frames[spinner_idx % len(spinner_frames)]}  Thinking...</span>",
                        "metadata": None,
                        "is_final": False,
                    }]
                elif delta.get('content', ''):
                    if is_reasoning:
                        is_reasoning = False
                    normal_content += delta['content']
                    temp = [{
                        "role": "assistant",
                        "content": normal_content,
                        "metadata": None,
                        "is_final": False,
                    }]

                yield {
                    chatbot: gr.update(value=ctx["history"] + temp),
                    state: gr.update(value=state_value),
                }

            if not is_reasoning and temp:
                ctx["history"].extend(temp)
                if ctx["history"][-1].get("role") == "assistant":
                    ctx["history"][-1]["is_final"] = True

            yield {
                chatbot: gr.update(value=ctx["history"]),
                state: gr.update(value=state_value),
                send_btn: gr.update(visible=True),
                stop_btn: gr.update(visible=False),
            }

        except Exception as exc:
            ctx["history"].append({
                "role": "assistant",
                "content": f'<span style="color: var(--color-red-500)">{exc}</span>',
            })
            yield {
                chatbot: gr.update(value=ctx["history"]),
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

            # Landing page shown when chat is empty
            landing_page = gr.HTML(
                value="""
                <div id="landing-page">
                    <div class="landing-content">
                        <div class="landing-logo">
                            <img src="/gradio_api/file=static/svg/logo.svg" alt="MythosHarness" width="420" height="70" />
                        </div>
                    </div>
                    <div class="landing-prompt">
                        <p>Made with ❤️ by KingNish and Himanshu</p>
                    </div>
                </div>
                """,
                elem_id="landing-page-container",
            )

            chatbot = gr.Chatbot(
                elem_id="chatbot",
                show_label=False,
                buttons=[],
                layout="bubble"
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
