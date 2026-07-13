"""Thin client for the Ollama chat API."""

import logging

import requests

from backend.config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_NUM_CTX, OLLAMA_TIMEOUT

logger = logging.getLogger(__name__)


class OllamaClient:
    def __init__(self, base_url=None, model=None, timeout=None, num_ctx=None):
        self.base_url = base_url or OLLAMA_BASE_URL
        self.model = model or OLLAMA_MODEL
        self.timeout = int(timeout or OLLAMA_TIMEOUT)
        self.num_ctx = int(num_ctx or OLLAMA_NUM_CTX)

    def chat(self, messages: list[dict]) -> str:
        """Send role-tagged messages to /api/chat and return the reply text."""
        response = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {"num_ctx": self.num_ctx},
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("message", {}).get("content", "")

    def chat_stream(self, messages: list[dict]):
        """Yield reply text fragments as Ollama generates them."""
        import json

        with requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": True,
                "options": {"num_ctx": self.num_ctx},
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
