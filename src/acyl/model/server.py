"""Local OpenAI-compatible server for Antares-350M (transformers)."""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from acyl.paths import models_dir


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = "fdtn-ai/antares-350m"
    messages: list[ChatMessage]
    temperature: float = 0.3
    top_p: float = 1.0
    max_tokens: int = 512


def build_app(model_id: str | None = None, mock: bool = False) -> FastAPI:
    state: dict[str, Any] = {"model": None, "tokenizer": None, "mock": mock, "model_id": model_id}

    def _load() -> None:
        mid = state["model_id"] or os.environ.get("ACYL_MODEL_ID") or "fdtn-ai/antares-350m"
        state["model_id"] = mid
        if state["mock"] or os.environ.get("ACYL_MODEL_MOCK") == "1":
            state["mock"] = True
            return
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "Install acyl[model] extras to serve Antares locally, or set ACYL_MODEL_MOCK=1"
            ) from exc
        cache = models_dir()
        cache.mkdir(parents=True, exist_ok=True)
        local = cache / mid.replace("/", "__")
        source = str(local) if local.exists() else mid
        tokenizer = AutoTokenizer.from_pretrained(source, cache_dir=str(cache))
        model = AutoModelForCausalLM.from_pretrained(source, cache_dir=str(cache))
        state["tokenizer"] = tokenizer
        state["model"] = model
        marker = cache / "ACTIVE_MODEL"
        marker.write_text(mid, encoding="utf-8")

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        _load()
        yield

    app = FastAPI(title="acyl local model", version="0.1.0", lifespan=lifespan)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "mock": state["mock"], "model": state["model_id"]}

    @app.get("/v1/models")
    def models() -> dict[str, Any]:
        return {
            "data": [{"id": state["model_id"] or "mock", "object": "model"}],
            "object": "list",
        }

    @app.post("/v1/chat/completions")
    def chat(req: ChatRequest) -> dict[str, Any]:
        if state["mock"]:
            content = _mock_completion(req.messages)
        else:
            content = _generate(state, req)
        return {
            "id": "acyl-chat",
            "object": "chat.completion",
            "model": req.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
        }

    return app


def _mock_completion(messages: list[ChatMessage]) -> str:
    """Deterministic mock that walks a fixture-like repo and submits app.py."""
    joined = "\n".join(m.content for m in messages)
    if "submit_vulnerable_files" in joined or joined.count("<tool_response>") >= 2:
        return (
            "<think>Enough evidence gathered.</think>\n"
            '<tool_call>{"name":"submit_vulnerable_files","arguments":{"files":["app.py","config.py"]}}</tool_call>'
        )
    if "<tool_response>" in joined:
        return (
            "<think>Inspecting likely sources.</think>\n"
            '<tool_call>{"name":"terminal","arguments":{"command":"grep -RIn \\"os.system\\|subprocess\\|password\\" --include=\\"*.py\\" ."}}</tool_call>'
        )
    return (
        "<think>Start by listing Python files.</think>\n"
        '<tool_call>{"name":"terminal","arguments":{"command":"find . -name \'*.py\' | head"}}</tool_call>'
    )


def _generate(state: dict[str, Any], req: ChatRequest) -> str:
    tokenizer = state["tokenizer"]
    model = state["model"]
    messages = [{"role": m.role, "content": m.content} for m in req.messages]
    inputs = tokenizer.apply_chat_template(
        messages,
        return_tensors="pt",
        add_generation_prompt=True,
        return_dict=True,
    )
    prompt_length = inputs["input_ids"].shape[-1]
    # use_cache=False: workaround for transformers GraniteMoeHybrid bug where
    # attention-only models (Antares/Granite 4.0 350M) crash with:
    # ValueError: has_previous_state can only be called on LinearAttention layers
    # (huggingface/transformers#45507). Remove when transformers is fixed.
    output = model.generate(
        **inputs,
        do_sample=True,
        temperature=req.temperature,
        top_p=req.top_p,
        max_new_tokens=req.max_tokens,
        use_cache=False,
    )
    return tokenizer.decode(output[0][prompt_length:], skip_special_tokens=False)


def run_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    model_id: str | None = None,
    mock: bool = False,
) -> None:
    import uvicorn

    app = build_app(model_id=model_id, mock=mock)
    uvicorn.run(app, host=host, port=port, log_level="info")
