"""Central configuration and logging setup for PacketIQ."""

import logging
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

PCAP_DIR = Path(os.getenv("PCAP_DIR", str(PROJECT_ROOT / "pcaps")))
LOG_BASE_DIR = Path(os.getenv("LOG_DIR", str(PROJECT_ROOT / "logs")))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", str(PROJECT_ROOT / "output")))

DATABASE_URL = os.getenv("DATABASE_URL")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "180"))
OLLAMA_NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "8192"))

ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
    if o.strip()
]


def setup_logging() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
