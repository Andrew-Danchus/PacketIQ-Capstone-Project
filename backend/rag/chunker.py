"""Convert DB rows into natural-language chunks for embedding."""

import json


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
