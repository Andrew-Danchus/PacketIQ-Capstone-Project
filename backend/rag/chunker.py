from pathlib import Path
from typing import List
import json


# ─── DB-row chunk functions (used by pipeline.py) ─────────────────────────────

def connection_to_chunk(row) -> str:
    return (
        f"At {row['ts']}, {row['src_ip']} connected to "
        f"{row['dst_ip']}:{row['dst_port']} using {row['proto']}. "
        f"Service: {row.get('service')}. Duration: {row.get('duration')}s. "
        f"Sent {row.get('orig_bytes')} bytes and received {row.get('resp_bytes')} bytes. "
        f"State: {row.get('conn_state')}."
    )


def aggregate_conn_to_chunk(row) -> str:
    return (
        f"{row['src_ip']} made {row['count']} connections to "
        f"{row['dst_ip']}:{row['dst_port']} via {row['proto']} "
        f"(service: {row.get('service') or 'unknown'}, state: {row['conn_state']}) "
        f"between timestamps {row['first_ts']} and {row['last_ts']}."
    )


def dns_to_chunk(row) -> str:
    return (
        f"At {row['ts']}, host {row['src_ip']} queried {row.get('query')} over DNS. "
        f"Destination {row.get('dst_ip')}:{row.get('dst_port')}. "
        f"Response code: {row.get('rcode')}. Answers: {row.get('answers')}."
    )


def http_to_chunk(row) -> str:
    return (
        f"At {row['ts']}, {row['src_ip']} made an HTTP {row.get('method')} request "
        f"to host {row.get('host')} URI {row.get('uri')}. "
        f"Status code: {row.get('status_code')}. User-Agent: {row.get('user_agent')}."
    )


def tls_to_chunk(row) -> str:
    return (
        f"At {row['ts']}, TLS traffic from {row['src_ip']} to {row['dst_ip']}. "
        f"Server name: {row.get('server_name')}. TLS version: {row.get('version')}. "
        f"Cipher: {row.get('cipher')}. Certificate: {row.get('cert')}."
    )


def detection_to_chunk(row) -> str:
    evidence = row.get("evidence")
    if isinstance(evidence, dict):
        evidence_text = json.dumps(evidence)
    else:
        evidence_text = str(evidence)

    return (
        f"Detection at {row['ts']}: {row['detection_type']} severity {row['severity']}. "
        f"Source IP: {row.get('src_ip')}. Destination IP: {row.get('dst_ip')}. "
        f"Destination port: {row.get('dst_port')}. Evidence: {evidence_text}."
    )

#cap chunks to keep RAG size manageable
MAX_CONN_CHUNKS = 500
MAX_DNS_CHUNKS = 200
MAX_WEIRD_CHUNKS = 100
MAX_NOTICE_CHUNKS = 100

def load_json_log(file_path: Path) -> List[dict]:
    """Load a Zeek JSON log file into a list of records."""
    records = []
    if not file_path.exists():
        return records

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return records


def chunk_conn_records(records: List[dict]) -> List[str]:
    """Convert conn.log records into natural language text chunks."""
    chunks = []
    for r in records:
        ts = r.get("ts", "unknown time")
        src = r.get("id.orig_h", "?")
        src_port = r.get("id.orig_p", "?")
        dst = r.get("id.resp_h", "?")
        dst_port = r.get("id.resp_p", "?")
        proto = r.get("proto", "?")
        service = r.get("service", "unknown service")
        duration = r.get("duration", None)
        orig_bytes = r.get("orig_bytes", None)
        resp_bytes = r.get("resp_bytes", None)
        conn_state = r.get("conn_state", "?")

        duration_str = f"over {duration:.2f}s" if isinstance(duration, (int, float)) else ""

        bytes_str = ""
        if orig_bytes is not None and resp_bytes is not None:
            bytes_str = f", transferred {orig_bytes}B sent / {resp_bytes}B received"

        chunk = (
            f"At {ts}, host {src}:{src_port} connected to {dst}:{dst_port} "
            f"via {proto} (service: {service}){bytes_str} {duration_str}. "
            f"Connection state: {conn_state}."
        )
        chunks.append(chunk)

    return chunks


def chunk_dns_records(records: List[dict]) -> List[str]:
    """Convert dns.log records into natural language text chunks."""
    chunks = []
    for r in records:
        ts = r.get("ts", "unknown time")
        src = r.get("id.orig_h", "?")
        dst = r.get("id.resp_h", "?")
        query = r.get("query", "?")
        qtype = r.get("qtype_name", "?")
        answers = r.get("answers", [])
        answer_str = ", ".join(answers) if isinstance(answers, list) else str(answers)

        chunk = (
            f"At {ts}, host {src} sent a DNS {qtype} query to {dst} for '{query}'. "
        )
        if answer_str:
            chunk += f"Response: {answer_str}."
        else:
            chunk += "No response recorded."

        chunks.append(chunk)

    return chunks


def chunk_weird_records(records: List[dict]) -> List[str]:
    """Convert weird.log records into natural language text chunks."""
    chunks = []
    for r in records:
        ts = r.get("ts", "unknown time")
        src = r.get("id.orig_h", "?")
        dst = r.get("id.resp_h", "?")
        name = r.get("name", "?")
        notice = r.get("notice", False)

        chunk = (
            f"At {ts}, Zeek flagged a weird event '{name}' on connection {src} -> {dst}."
        )
        if notice:
            chunk += " This event was escalated to a notice."

        chunks.append(chunk)

    return chunks


def chunk_notice_records(records: List[dict]) -> List[str]:
    """Convert notice.log records into natural language text chunks."""
    chunks = []
    for r in records:
        ts = r.get("ts", "unknown time")
        src = r.get("id.orig_h", "?")
        dst = r.get("id.resp_h", "?")
        note = r.get("note", "?")
        msg = r.get("msg", "")

        chunk = (
            f"At {ts}, Zeek raised a notice '{note}' on connection {src} -> {dst}. "
            f"Details: {msg}"
        )
        chunks.append(chunk)

    return chunks


def chunk_detection_alerts(results: dict) -> List[str]:
    """Convert detection alert dicts into natural language text chunks."""
    chunks = []

    for alert in results.get("port_scans", []):
        sample = ", ".join(str(p) for p in alert.get("sample_ports", []))
        chunk = (
            f"Detection alert [PORT SCAN]: Source IP {alert['src_ip']} contacted "
            f"{alert['unique_ports']} unique destination ports and {alert['unique_hosts']} unique hosts "
            f"within {alert['window_secs']} seconds "
            f"(timestamps {alert['first_seen_ts']} to {alert['last_seen_ts']}). "
            f"Sample ports scanned: {sample}."
        )
        chunks.append(chunk)

    for alert in results.get("ddos", []):
        chunk = (
            f"Detection alert [DDOS]: Target IP {alert['dst_ip']} received "
            f"{alert['total_connections']} connections from {alert['unique_src_ips']} unique source IPs, "
            f"totaling {alert['total_bytes']} bytes within {alert['window_secs']} seconds "
            f"(timestamps {alert['first_seen_ts']} to {alert['last_seen_ts']})."
        )
        chunks.append(chunk)

    for alert in results.get("brute_force", []):
        window = alert.get("window_secs")
        first_ts = alert.get("first_seen_ts")
        last_ts = alert.get("last_seen_ts")

        time_str = f" within {window} seconds" if window is not None else ""
        ts_str = f" (timestamps {first_ts} to {last_ts})" if first_ts is not None else ""

        chunk = (
            f"Detection alert [BRUTE FORCE]: Source IP {alert['src_ip']} made "
            f"{alert['failed_attempts']} failed connection attempts out of {alert['total_attempts']} total "
            f"to {alert['dst_ip']}:{alert['dst_port']}{time_str}{ts_str}."
        )
        chunks.append(chunk)

    return chunks


def build_chunks_from_logs(log_dir: Path) -> List[str]:
    """Load all Zeek logs from log_dir and return a flat list of text chunks."""
    chunks = []

    conn_records = load_json_log(log_dir / "conn.log")
    chunks.extend(chunk_conn_records(conn_records[:MAX_CONN_CHUNKS]))

    dns_records = load_json_log(log_dir / "dns.log")
    chunks.extend(chunk_dns_records(dns_records[:MAX_DNS_CHUNKS]))

    weird_records = load_json_log(log_dir / "weird.log")
    chunks.extend(chunk_weird_records(weird_records[:MAX_WEIRD_CHUNKS]))

    notice_records = load_json_log(log_dir / "notice.log")
    chunks.extend(chunk_notice_records(notice_records[:MAX_NOTICE_CHUNKS]))

    return chunks
