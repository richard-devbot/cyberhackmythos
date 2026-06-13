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

JS_LOAD_STATE = """(_) => {
    const titles = JSON.parse(localStorage.getItem("titles") || "{}");
    const conversations = [];
    const conversation_contexts = {};

    for (const [id, label] of Object.entries(titles)) {
        const raw = localStorage.getItem("chat_id_" + id);
        if (raw) {
            conversations.push({ key: id, label: label });
            conversation_contexts[id] = JSON.parse(raw);
        }
    }

    return JSON.stringify({ conversations, conversation_contexts });
}"""

JS_SAVE_STATE = """(stateJson) => {
    const state = JSON.parse(stateJson);
    const titles = {};

    for (const conv of (state.conversations || [])) {
        titles[conv.key] = conv.label;
        const ctx = (state.conversation_contexts || {})[conv.key];
        if (ctx !== undefined) {
            localStorage.setItem("chat_id_" + conv.key, JSON.stringify(ctx));
        }
    }

    // Remove stale chat_id_* keys that are no longer in conversations
    const validIds = new Set(Object.keys(titles));
    for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.startsWith("chat_id_")) {
            const id = k.slice("chat_id_".length);
            if (!validIds.has(id)) {
                localStorage.removeItem(k);
                i--;  // adjust index after removal
            }
        }
    }

    localStorage.setItem("titles", JSON.stringify(titles));
    return stateJson;
}"""


def _conv_choices(state_value):
    return gr.update(
        choices=[(c["label"], c["key"]) for c in state_value["conversations"]],
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
                {"label": message[:30], "key": conv_id})
            state_value["conversation_contexts"][conv_id] = {
                "history": []
            }
        else:
            conv_id = state_value["conversation_id"]
            state_value["conversation_contexts"].setdefault(
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

css = open("./app.css", "r").read()

with gr.Blocks(fill_width=True, title="Demo Chat") as demo:
    state = gr.State({
        "conversation_contexts": {},
        "conversations": [],
        "conversation_id": "",
    })

    js_load_output = gr.Textbox(visible=False, elem_id="js-load-output")
    js_save_input  = gr.Textbox(visible=False, elem_id="js-save-input")

    with gr.Row(elem_id="main-row"):
        with gr.Sidebar():
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
                            <svg width="300" height="42" viewBox="0 0 300 42" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M0 6H24V12H0V6ZM0 12H6V18H0V12ZM18 12H24V18H18V12ZM30 6H54V12H30V6ZM30 12H36V18H30V12ZM30 36H36V42H30V36ZM48 12H54V18H48V12ZM60 6H84V12H60V6ZM60 12H66V18H60V12ZM78 12H84V18H78V12ZM90 6H114V12H90V6ZM90 12H96V18H90V12ZM108 12H114V18H108V12ZM120 6H150V12H120V6ZM120 12H126V18H120V12ZM132 12H138V18H132V12ZM144 12H150V18H144V12ZM156 6H162V18H156V6ZM174 6H180V18H174V6ZM174 36H180V42H174V36ZM186 6H210V12H186V6ZM192 0H198V6H192V0ZM192 12H198V18H192V12ZM216 0H222V12H216V0ZM216 12H240V18H216V12ZM246 6H270V12H246V6ZM246 12H252V18H246V12ZM264 12H270V18H264V12ZM276 6H300V12H276V6ZM276 12H282V18H276V12Z" fill="#F1ECEC"/>
                                <path d="M0 18H6V30H0V18ZM0 30H24V36H0V30ZM18 18H24V30H18V18ZM30 18H36V30H30V18ZM30 30H54V36H30V30ZM48 18H54V30H48V18ZM60 18H84V24H60V18ZM60 24H66V30H60V24ZM60 30H84V36H60V30ZM90 18H96V36H90V18ZM108 18H114V36H108V18ZM120 18H126V36H120V18ZM132 18H138V24H132V18ZM144 18H150V36H144V18ZM156 18H162V24H156V18ZM156 24H180V30H156V24ZM174 18H180V24H174V18ZM174 30H180V36H174V30ZM192 18H198V30H192V18ZM192 30H204V36H192V30ZM216 18H222V36H216V18ZM234 18H240V36H234V18ZM246 18H252V30H246V18ZM246 30H270V36H246V30ZM264 18H270V30H264V18ZM276 18H300V24H276V18ZM276 30H300V36H276V30ZM294 24H300V30H294V24Z" fill="#B7B1B1"/>
                            </svg>
                        </div>
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
        fn=lambda x: x,
        inputs=[js_load_output],
        outputs=[js_load_output],
        js=JS_LOAD_STATE,
    ).then(
        fn=GradioEvents.load_from_js,
        inputs=[js_load_output, state],
        outputs=[conv_choice, state],
    ).then(
        fn=None,
        inputs=None,
        outputs=None,
        js="""
        () => {
            // Landing page toggle logic
            const landingPage = document.getElementById('landing-page-container');
            const chatbot = document.getElementById('chatbot');
            const msgInput = document.querySelector('#input-row textarea, #input-row input[type="text"]');

            if (!landingPage || !chatbot) return;

            function toggleLanding() {
                // Check if chatbot has any messages
                const messages = chatbot.querySelectorAll('[data-testid="bot"], [data-testid="user"], [class*="message"]');
                const hasMessages = messages.length > 0;

                // Also check for empty state indicators
                const emptyState = chatbot.querySelector('.empty-state, .placeholder, [class*="empty"]');
                const chatColumn = document.getElementById('chat-column');

                if (hasMessages && !emptyState) {
                    landingPage.classList.add('hidden');
                    if (chatColumn) chatColumn.classList.remove('landing-active');
                } else {
                    landingPage.classList.remove('hidden');
                    if (chatColumn) chatColumn.classList.add('landing-active');
                }
            }

            // Initial check
            toggleLanding();

            // Set up mutation observer to watch for chat changes
            const observer = new MutationObserver((mutations) => {
                let shouldToggle = false;
                for (const mutation of mutations) {
                    if (mutation.type === 'childList' || mutation.type === 'subtree') {
                        shouldToggle = true;
                        break;
                    }
                }
                if (shouldToggle) {
                    // Debounce the toggle check
                    clearTimeout(window._landingToggleTimeout);
                    window._landingToggleTimeout = setTimeout(toggleLanding, 100);
                }
            });

            observer.observe(chatbot, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['class']
            });

            // Also watch for the input area to handle new chat creation
            const inputRow = document.getElementById('input-row');
            if (inputRow) {
                observer.observe(inputRow, {
                    childList: true,
                    subtree: true
                });
            }

            // Click on landing prompt to focus input
            const landingPrompt = document.querySelector('.landing-prompt');
            if (landingPrompt && msgInput) {
                landingPrompt.addEventListener('click', () => {
                    msgInput.focus();
                    msgInput.click();
                });
            }

            // Store reference for cleanup
            window._landingPageObserver = observer;
            window._landingPage = landingPage;
        }
        """,
    )

theme = gr.themes.Base(radius_size="none")

if __name__ == "__main__":
    demo.queue(default_concurrency_limit=100, max_size=100).launch(ssr_mode=False, max_threads=100, css=css, theme=theme)
