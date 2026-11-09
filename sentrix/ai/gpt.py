"""Minimal OpenAI-compatible chat client using only the standard library."""
from __future__ import annotations

import json
import urllib.request
from sentrix.core.net import assert_safe_outbound_url


class GPTClient:
    def __init__(self, base_url: str, model: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key

    def chat(self, messages: list[dict], temperature: float = 0.1) -> str:
        url = f"{self.base_url}/chat/completions"
        assert_safe_outbound_url(url)
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps({
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
            }).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
        return body["choices"][0]["message"]["content"]