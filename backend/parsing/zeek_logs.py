"""Shared loader for Zeek JSON logs (one JSON object per line)."""

import json
from pathlib import Path


def load_json_log(file_path: Path | str) -> list[dict]:
    file_path = Path(file_path)
    records: list[dict] = []

    if not file_path.exists():
        return records

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return records
