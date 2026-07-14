"""Thin client for the Ollama chat API."""

import json
import logging

import requests

from backend.config import (
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OLLAMA_NUM_CTX,
    OLLAMA_TEMPERATURE,
    OLLAMA_TIMEOUT,
)

logger = logging.getLogger(__name__)


class OllamaClient:
    def __init__(self, base_url=None, model=None, timeout=None, num_ctx=None, temperature=None):
        self.base_url = base_url or OLLAMA_BASE_URL
        self.model = model or OLLAMA_MODEL
        self.timeout = int(timeout or OLLAMA_TIMEOUT)
        self.num_ctx = int(num_ctx or OLLAMA_NUM_CTX)
        self.temperature = OLLAMA_TEMPERATURE if temperature is None else temperature

    def _options(self, temperature=None) -> dict:
        return {
            "num_ctx": self.num_ctx,
            "temperature": self.temperature if temperature is None else temperature,
        }

    def chat(self, messages: list[dict], temperature=None, fmt=None) -> str:
        """Send role-tagged messages to /api/chat and return the reply text."""
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": self._options(temperature),
        }
        if fmt is not None:
            payload["format"] = fmt

        response = requests.post(
            f"{self.base_url}/api/chat",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("message", {}).get("content", "")

    def chat_stream(self, messages: list[dict], temperature=None):
        """Yield reply text fragments as Ollama generates them."""
        with requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": True,
                "options": self._options(temperature),
            },
            timeout=self.timeout,
            stream=True,
        ) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if not line:
                    continue
                data = json.loads(line)
                fragment = data.get("message", {}).get("content", "")
                if fragment:
                    yield fragment
                if data.get("done"):
                    break
