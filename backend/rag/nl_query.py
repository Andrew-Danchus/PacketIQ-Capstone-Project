"""Translate a natural-language connections query into structured filter params.

The LLM only ever emits the same filter fields the /connections endpoint
already accepts (src_ip, dst_ip, dst_port, conn_state) — never raw SQL — so the
parameterized query stays injection-safe.
"""

import ipaddress
import json
import logging
import re

from backend.ollama.client import OllamaClient

logger = logging.getLogger(__name__)

client = OllamaClient()

VALID_STATES = {"SF", "S0", "S1", "S2", "S3", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}
# A short vocabulary so the model maps common words to Zeek states / ports.
_HINTS = """\
Filter fields you may set (all optional):
- src_ip: source IP address (exact)
- dst_ip: destination IP address (exact)
- dst_port: destination port number (integer)
- conn_state: Zeek connection state. Valid values: SF (completed), S0 (no reply),
  REJ (rejected), RSTO/RSTR (reset), OTH (other). "failed" usually means S0 or REJ.

Common service-to-port mappings: ssh=22, ftp=21, telnet=23, smtp=25, dns=53,
http/web=80, https=443, rdp=3389, smb=445, mysql=3306, postgres=5432, vnc=5900.
"""

_SYSTEM = f"""\
You convert a network analyst's plain-English request into a JSON filter for a
connections table. Only output JSON with these optional keys: src_ip, dst_ip,
dst_port, conn_state. Omit keys you can't determine. Never guess an IP that
isn't in the request. If the request mentions a service by name, map it to its
port. If it says "failed", set conn_state to the single best match (S0 or REJ).

{_HINTS}

Respond with only the JSON object, nothing else."""


def _valid_ip(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def parse_connection_query(query: str) -> dict:
    """Return a dict with any of src_ip/dst_ip/dst_port/conn_state the model
    could extract. Best-effort — an unparseable query yields {}."""
    messages = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": query},
    ]

    try:
        raw = client.chat(messages, temperature=0, fmt="json")
        data = json.loads(raw)
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("NL query parse failed for %r: %s", query, e)
        # Last-ditch: pull an explicit "port N" out of the text.
        m = re.search(r"\bport\s+(\d{1,5})\b", query, re.IGNORECASE)
        return {"dst_port": int(m.group(1))} if m else {}

    filters: dict = {}

    for key in ("src_ip", "dst_ip"):
        ip = _valid_ip(data.get(key))
        if ip:
            filters[key] = ip

    port = data.get("dst_port")
    try:
        if port is not None and 0 < int(port) <= 65535:
            filters["dst_port"] = int(port)
    except (TypeError, ValueError):
        pass

    state = data.get("conn_state")
    if isinstance(state, str) and state.upper() in VALID_STATES:
        filters["conn_state"] = state.upper()

    return filters
