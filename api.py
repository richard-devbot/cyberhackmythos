"""FastAPI backend bridging the Next.js console to the Python security engine.

Endpoints
  POST /api/chat            Server-Sent Events stream of agent events
  GET  /api/findings        Live, deduplicated findings + severity summary
  POST /api/findings/clear  Reset the findings store
  GET  /api/meta            Sandbox isolation tier, available scanners, model

Run:  uvicorn api:app --port 8000  (or: python api.py)
"""

from __future__ import annotations

import json
import os
from typing import Generator

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

load_dotenv()

from agent.findings import dedupe, summarize  # noqa: E402
from agent.sandbox import get_sandbox  # noqa: E402
from agent.scanners import all_scanners, clear_findings_store, get_findings_store  # noqa: E402
from engine import build_agent  # noqa: E402

# MCP registration hits 4 external servers at startup; off by default for a snappy
# API. Set CYBERHACKMYTHOS_ENABLE_MCP=true to include the web-search MCP tools.
_ENABLE_MCP = os.getenv("CYBERHACKMYTHOS_ENABLE_MCP", "false").strip().lower() in ("1", "true", "yes")
agent = build_agent(enable_mcp=_ENABLE_MCP)

# In-memory conversation histories, keyed by client-supplied session id.
_SESSIONS: dict[str, list[dict]] = {}

app = FastAPI(title="cyberhackmythos API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatRequest(BaseModel):
    session_id: str
    message: str


class SetModelRequest(BaseModel):
    model: str
    base_url: str | None = None  # for self-hosted endpoints (e.g. Colab-tunneled vLLM/Ollama)
    api_key: str | None = None


# Curated, NIM-verified picks for the dropdown (plus a self-hosted escape hatch).
RECOMMENDED_MODELS = [
    {"id": "openai/gpt-oss-120b", "label": "gpt-oss-120b · balanced default",
     "note": "reasons + answers well; may refuse some offensive tasks"},
    {"id": "deepseek-ai/deepseek-v4-pro", "label": "deepseek-v4-pro · strong coder", "note": ""},
    {"id": "nvidia/nemotron-3-nano-30b-a3b", "label": "nemotron-3-nano · fast", "note": "3B active"},
    {"id": "qwen/qwen3-next-80b-a3b-instruct", "label": "qwen3-next-80b · fast", "note": "3B active"},
]


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event)}\n\n"


@app.post("/api/chat")
def chat(req: ChatRequest) -> StreamingResponse:
    """Stream the agent's reasoning/text/tool events for one user turn."""
    history = _SESSIONS.setdefault(req.session_id, [])
    history.append({"role": "user", "content": req.message})

    def generate() -> Generator[str, None, None]:
        try:
            for ev in agent.stream(history):
                yield _sse(ev)
        except Exception as exc:  # noqa: BLE001 - surface any engine error to the client
            yield _sse({"type": "error", "content": str(exc)})
        yield _sse({"type": "end"})

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/findings")
def findings() -> JSONResponse:
    fs = dedupe(get_findings_store())
    return JSONResponse(
        {
            "findings": [f.to_dict() for f in fs],
            "summary": summarize(fs),
        }
    )


@app.post("/api/findings/clear")
def clear() -> JSONResponse:
    clear_findings_store()
    return JSONResponse({"ok": True})


@app.get("/api/meta")
def meta() -> JSONResponse:
    sb = get_sandbox()
    return JSONResponse(
        {
            "isolation": sb.isolation_level,
            "backend": sb.backend,
            "scanners": [s.name for s in all_scanners()],
            "model": agent.model,
            "mcp_enabled": _ENABLE_MCP,
        }
    )


@app.get("/api/models")
def models() -> JSONResponse:
    return JSONResponse({"current": agent.model, "recommended": RECOMMENDED_MODELS})


@app.post("/api/model")
def set_model(req: SetModelRequest) -> JSONResponse:
    """Switch the active model at runtime — no restart, no tool re-registration.

    Optionally repoint at a self-hosted OpenAI-compatible endpoint (base_url/api_key),
    e.g. a Colab-tunneled vLLM/Ollama serving WhiteRabbitNeo or OpenMythos.
    """
    from openai import OpenAI

    if not req.model.strip():
        return JSONResponse({"ok": False, "error": "model is required"}, status_code=400)
    agent.model = req.model.strip()
    if req.base_url:
        agent.client = OpenAI(
            base_url=req.base_url.strip(),
            api_key=(req.api_key or os.getenv("OPENAI_API_KEY") or "not-needed").strip(),
        )
    return JSONResponse({"ok": True, "model": agent.model})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("CYBERHACKMYTHOS_API_PORT", "8000")))
