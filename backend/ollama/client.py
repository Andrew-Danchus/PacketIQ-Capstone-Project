import requests
from .config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT, OLLAMA_NUM_CTX


class OllamaClient:
    def __init__(self, base_url=OLLAMA_BASE_URL, model=OLLAMA_MODEL):
        self.base_url = base_url
        self.model = model

    def chat(self, messages, stream=False):
        response = requests.post(
        f"{self.base_url}/api/chat",
        json={
            "model": self.model,
            "messages": messages,
            "stream": stream,
            "keep_alive": "10m",
            "options": {
            "num_ctx": OLLAMA_NUM_CTX
        }
    },
    timeout=OLLAMA_TIMEOUT
)
        response.raise_for_status()
        return response.json()