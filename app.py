import time
import uuid
import gradio as gr
from openai import OpenAI
from dotenv import load_dotenv
import os

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
    base_url=os.getenv("OPENAI_BASE_URL"),
)
model = os.getenv("OPENAI_MODEL")


def _conv_choices(state_value):
    return gr.update(
        choices=[c["label"] for c in state_value["conversations"]],
        value=next(
            (c["label"] for c in state_value["conversations"]
             if c["key"] == state_value.get("conversation_id")), None),
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
                {"label": message[:30], "key": conv_id})
            state_value["conversation_contexts"][conv_id] = {
                "history": []
            }
        else:
            conv_id = state_value["conversation_id"]
            ctx = state_value["conversation_contexts"].setdefault(
                conv_id, {"history": []})

        ctx = state_value["conversation_contexts"][conv_id]

        for c in state_value["conversations"]:
            if c["key"] == conv_id and not c.get("label"):
                c["label"] = message[:30]
                break

        ctx["history"].append({"role": "user", "content": message})

        yield { msg: gr.update(value=""), chatbot: gr.update(value=ctx["history"]), state: gr.update(value=state_value), conv_choice: _conv_choices(state_value), send_btn: gr.update(visible=False), stop_btn: gr.update(visible=True)}

        reasoning_content = ""
        normal_content = ""
        reasoning_started = False
        start_time = time.time()
        partial = []
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

                if delta.get('reasoning_content'):
                    reasoning_content += delta['reasoning_content']
                    if not reasoning_started:
                        start_time = time.time()
                        if normal_content:
                            partial.append({
                                "role": "assistant",
                                "content": normal_content,
                                "metadata": None,
                                "is_final": True,
                            })
                            normal_content = ""
                        reasoning_started = True
                    temp = [{
                        "role": "assistant",
                        "content": reasoning_content,
                        "metadata": {"title": "Thinking..."},
                        "is_final": False,
                    }]
                elif delta.get('content', ''):
                    if reasoning_started:
                        reasoning_started = False
                        partial.append({
                            "role": "assistant",
                            "content": reasoning_content,
                            "metadata": {"title": "Thought for " + f"{time.time() - start_time:.2f}s"},
                            "is_final": True,
                        })
                        reasoning_content = ""
                    normal_content += delta['content']
                    temp = [{
                        "role": "assistant",
                        "content": normal_content,
                        "metadata": None,
                        "is_final": False,
                    }]

                yield {
                    chatbot: gr.update(value=ctx["history"] + partial + temp),
                    state: gr.update(value=state_value),
                }

            ctx["history"].extend(partial)
            if temp:
                ctx["history"].extend(temp)
            if ctx["history"] and ctx["history"][-1].get("role") == "assistant":
                ctx["history"][-1]["is_final"] = True

            yield {
                chatbot: gr.update(value=ctx["history"]),
                state: gr.update(value=state_value),
                send_btn: gr.update(visible=True),
                stop_btn: gr.update(visible=False),
            }

        except Exception as exc:
            print("model:", model, "-", "Error:", exc)
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
            raise

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
        conv_id = None
        for c in state_value["conversations"]:
            if c["label"] == choice:
                conv_id = c["key"]
                break
        if not conv_id or conv_id == state_value.get("conversation_id"):
            return gr.skip()

        state_value["conversation_id"] = conv_id
        ctx = state_value["conversation_contexts"].get(conv_id, {})
        return (
            gr.update(value=ctx.get("history", [])),
            gr.update(value=state_value),
        )

    @staticmethod
    def delete_selected_conversation(choice, state_value):
        if not choice:
            return gr.skip()
        target_id = None
        for c in state_value["conversations"]:
            if c["label"] == choice:
                target_id = c["key"]
                break
        if not target_id:
            return gr.skip()

        state_value["conversation_contexts"].pop(target_id, None)
        state_value["conversations"] = [
            c for c in state_value["conversations"] if c["key"] != target_id
        ]
        was_active = state_value.get("conversation_id") == target_id
        if was_active:
            state_value["conversation_id"] = ""
            return (
                _conv_choices(state_value),
                gr.update(value=None),
                gr.update(value=True),
                gr.update(value=state_value),
            )
        return (
            _conv_choices(state_value),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.update(value=state_value),
        )

    @staticmethod
    def clear_history(state_value):
        if not state_value.get("conversation_id"):
            return gr.skip()
        state_value["conversation_contexts"][
            state_value["conversation_id"]]["history"] = []
        return gr.update(value=[]), gr.update(value=state_value)

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
        return (gr.update(value=ctx.get("history", [])),
                gr.update(value=state_value), gr.update(visible=True),
                gr.update(visible=False))

    @staticmethod
    def save_browser_state(state_value):
        return gr.update(value=dict(
            conversations=state_value["conversations"],
            conversation_contexts=state_value["conversation_contexts"]))

    @staticmethod
    def load_browser_state(browser_state_value, state_value):
        if not browser_state_value:
            return gr.skip(), gr.skip()
        state_value["conversations"] = browser_state_value.get("conversations", [])
        state_value["conversation_contexts"] = browser_state_value.get("conversation_contexts", {})
        return _conv_choices(state_value), gr.update(value=state_value)

css = open("./app.css", "r").read()

with gr.Blocks(fill_width=True, title="Demo Chat") as demo:
    state = gr.State({
        "conversation_contexts": {},
        "conversations": [],
        "conversation_id": "",
    })

    with gr.Row(elem_id="main-row"):
        with gr.Column(scale=0, min_width=260, elem_id="sidebar"):
            new_chat_btn = gr.Button(
                value="New Conversation",
                variant="primary",
            )
            conv_choice = gr.Radio(
                choices=[],
                label="Conversations",
                interactive=True,
                elem_id="conversations-radio",
            )
            delete_btn = gr.Button(
                value="Delete Selected",
                variant="stop",
            )

        with gr.Column(scale=1, elem_id="chat-column"):
            with gr.Row():
                clear_btn = gr.Button(
                    value="Clear History",
                    scale=0,
                    min_width=120,
                    visible=False,
                )

            chatbot = gr.Chatbot(
                elem_id="chatbot",
                show_label=False,
                buttons=[],
                layout="bubble"
            )
            with gr.Row():
                msg = gr.Textbox(
                    placeholder="Type a message and press Enter...",
                    show_label=False,
                    scale=4,
                    container=False,
                )
                send_btn = gr.Button(
                    "Send",
                    variant="primary",
                    scale=0,
                    min_width=80,
                )
                stop_btn = gr.Button(
                    "Stop",
                    variant="stop",
                    scale=0,
                    min_width=80,
                    visible=False,
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

    clear_btn.click(
        fn=GradioEvents.clear_history,
        inputs=[state],
        outputs=[chatbot, state],
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

    browser_state = gr.BrowserState(
        {
            "conversation_contexts": {},
            "conversations": [],
        },
        storage_key="chat_app_state"
    )
    state.change(
        fn=GradioEvents.save_browser_state,
        inputs=[state],
        outputs=[browser_state],
    )
    demo.load(
        fn=GradioEvents.load_browser_state,
        inputs=[browser_state, state],
        outputs=[conv_choice, state],
    )

theme = gr.themes.Base(radius_size="none")

if __name__ == "__main__":
    demo.queue(default_concurrency_limit=100, max_size=100).launch(ssr_mode=False, max_threads=100, css=css, theme=theme)
