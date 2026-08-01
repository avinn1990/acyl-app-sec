"""OpenAI-compatible chat client for localhost models."""

from __future__ import annotations

import os
from typing import Any

import httpx


class ChatClient:
    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.base_url = (base_url or os.environ.get("ACYL_MODEL_URL") or "http://127.0.0.1:8080/v1").rstrip(
            "/"
        )
        self.model = model or os.environ.get("ACYL_MODEL_ID") or "fdtn-ai/antares-350m"
        self.timeout = timeout

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.3,
        top_p: float = 1.0,
        max_tokens: int = 512,
    ) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "top_p": top_p,
            "max_tokens": max_tokens,
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(f"{self.base_url}/chat/completions", json=payload)
            resp.raise_for_status()
            data = resp.json()
        return data["choices"][0]["message"]["content"]
