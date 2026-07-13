"""Deterministic SQL facts for the LLM prompt.

Vector similarity is a weak fit for quantitative questions ("how many
connections hit port 445?"), so alongside the RAG chunks we compute exact
aggregates from Postgres, targeted at whatever the question mentions:
specific IPs, specific ports, and topic keywords (DNS/HTTP/TLS/failures).
The result is a plain-text block the model can cite directly.
"""

import logging
import re

from psycopg.rows import dict_row

from backend.db.jobs import get_conn

logger = logging.getLogger(__name__)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)

TOP_N = 10


def _rows(cur, query: str, params: tuple) -> list[dict]:
    cur.execute(query, params)
    return cur.fetchall()


def _capture_totals(cur, job_id) -> list[str]:
    row = _rows(
        cur,
        """
        SELECT COUNT(*) AS conns,
               COUNT(DISTINCT src_ip) AS srcs,
               COUNT(DISTINCT dst_ip) AS dsts,
               MIN(ts) AS first_ts, MAX(ts) AS last_ts
        FROM connections WHERE job_id = %s
        """,
        (job_id,),
    )[0]
    lines = [
        f"Total connections: {row['conns']}; unique source IPs: {row['srcs']}; "
        f"unique destination IPs: {row['dsts']}."
    ]
    if row["first_ts"] and row["last_ts"]:
        span = (row["last_ts"] - row["first_ts"]).total_seconds()
        lines.append(f"Capture spans {span:.1f} seconds ({row['first_ts']} to {row['last_ts']}).")
    return lines


def _top_talkers(cur, job_id) -> list[str]:
    lines = ["Top source IPs by connection count:"]
    for r in _rows(
        cur,
        """
        SELECT src_ip, COUNT(*) AS count,
               SUM(COALESCE(orig_bytes,0) + COALESCE(resp_bytes,0)) AS bytes
        FROM connections WHERE job_id = %s AND src_ip IS NOT NULL
        GROUP BY src_ip ORDER BY count DESC LIMIT %s
        """,
        (job_id, TOP_N),
    ):
        lines.append(f"- {r['src_ip']}: {r['count']} connections, {r['bytes'] or 0} bytes total")
    return lines


def _ip_profile(cur, job_id, ip: str) -> list[str]:
    lines = [f"Exact database facts for IP {ip}:"]

    as_src = _rows(
        cur,
        """
        SELECT dst_ip, dst_port, conn_state, COUNT(*) AS count
        FROM connections WHERE job_id = %s AND src_ip = %s
        GROUP BY dst_ip, dst_port, conn_state ORDER BY count DESC LIMIT %s
        """,
        (job_id, ip, TOP_N),
    )
    total_src = _rows(
        cur,
        "SELECT COUNT(*) AS c FROM connections WHERE job_id = %s AND src_ip = %s",
        (job_id, ip),
    )[0]["c"]
    if total_src:
        lines.append(f"As source: {total_src} connections. Top destinations:")
        lines.extend(
            f"- to {r['dst_ip']}:{r['dst_port']} state {r['conn_state']}: {r['count']}x"
            for r in as_src
        )

    total_dst = _rows(
        cur,
        "SELECT COUNT(*) AS c FROM connections WHERE job_id = %s AND dst_ip = %s",
        (job_id, ip),
    )[0]["c"]
    if total_dst:
        as_dst = _rows(
            cur,
            """
            SELECT src_ip, dst_port, conn_state, COUNT(*) AS count
            FROM connections WHERE job_id = %s AND dst_ip = %s
            GROUP BY src_ip, dst_port, conn_state ORDER BY count DESC LIMIT %s
            """,
            (job_id, ip, TOP_N),
        )
        lines.append(f"As destination: {total_dst} connections. Top sources:")
        lines.extend(
            f"- from {r['src_ip']} to port {r['dst_port']} state {r['conn_state']}: {r['count']}x"
            for r in as_dst
        )

    if not total_src and not total_dst:
        lines.append("This IP does not appear in the capture's connection log.")
    return lines


def _port_profile(cur, job_id, port: int) -> list[str]:
    total = _rows(
        cur,
        "SELECT COUNT(*) AS c FROM connections WHERE job_id = %s AND dst_port = %s",
        (job_id, port),
    )[0]["c"]

    lines = [f"Exact database facts for destination port {port}: {total} connections."]
    if total:
        for r in _rows(
            cur,
            """
            SELECT src_ip, dst_ip, conn_state, service, COUNT(*) AS count
            FROM connections WHERE job_id = %s AND dst_port = %s
            GROUP BY src_ip, dst_ip, conn_state, service ORDER BY count DESC LIMIT %s
            """,
            (job_id, port, TOP_N),
        ):
            lines.append(
                f"- {r['src_ip']} -> {r['dst_ip']} state {r['conn_state']} "
                f"(service: {r['service'] or 'unknown'}): {r['count']}x"
            )
    return lines


def _failed_summary(cur, job_id) -> list[str]:
    lines = ["Connection state breakdown (S0=no reply, REJ=rejected, SF=completed):"]
    for r in _rows(
        cur,
        """
        SELECT conn_state, COUNT(*) AS count
        FROM connections WHERE job_id = %s AND conn_state IS NOT NULL
        GROUP BY conn_state ORDER BY count DESC
        """,
        (job_id,),
    ):
        lines.append(f"- {r['conn_state']}: {r['count']}")
    return lines


def _dns_summary(cur, job_id) -> list[str]:
    lines = ["Top DNS queries:"]
    for r in _rows(
        cur,
        """
        SELECT query, COUNT(*) AS count
        FROM dns_events WHERE job_id = %s AND query IS NOT NULL
        GROUP BY query ORDER BY count DESC LIMIT %s
        """,
        (job_id, TOP_N),
    ):
        lines.append(f"- {r['query']}: {r['count']}x")
    return lines if len(lines) > 1 else ["No DNS events recorded in this capture."]


def _http_summary(cur, job_id) -> list[str]:
    lines = ["Top HTTP requests (host, URI, status, count):"]
    for r in _rows(
        cur,
        """
        SELECT host, uri, status_code, COUNT(*) AS count
        FROM http_events WHERE job_id = %s
        GROUP BY host, uri, status_code ORDER BY count DESC LIMIT %s
        """,
        (job_id, TOP_N),
    ):
        lines.append(f"- {r['host']}{r['uri']} -> {r['status_code']}: {r['count']}x")
    return lines if len(lines) > 1 else ["No HTTP events recorded in this capture."]


def _tls_summary(cur, job_id) -> list[str]:
    lines = ["TLS servers observed (SNI, version, count):"]
    for r in _rows(
        cur,
        """
        SELECT server_name, version, COUNT(*) AS count
        FROM tls_events WHERE job_id = %s
        GROUP BY server_name, version ORDER BY count DESC LIMIT %s
        """,
        (job_id, TOP_N),
    ):
        lines.append(f"- {r['server_name'] or '(no SNI)'} {r['version'] or ''}: {r['count']}x")
    return lines if len(lines) > 1 else ["No TLS events recorded in this capture."]


KEYWORD_SECTIONS = [
    ({"top", "most", "active", "talker", "busiest", "who"}, _top_talkers),
    ({"fail", "failed", "reject", "state", "incomplete", "drop"}, _failed_summary),
    ({"dns", "domain", "query", "lookup", "resolve"}, _dns_summary),
    ({"http", "web", "url", "uri", "request", "user-agent", "useragent"}, _http_summary),
    ({"tls", "ssl", "https", "cert", "certificate", "cipher", "encrypt"}, _tls_summary),
]


def build_sql_context(job_id, question: str) -> str:
    """Compute exact aggregates relevant to the question. Never raises —
    retrieval must not take the chat down."""
    try:
        words = set(re.findall(r"[a-z-]+", question.lower()))
        ips = list(dict.fromkeys(IP_RE.findall(question)))[:3]
        ports = [int(p) for p in dict.fromkeys(PORT_RE.findall(question))][:3]

        sections: list[list[str]] = []

        with get_conn() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                sections.append(_capture_totals(cur, job_id))

                for ip in ips:
                    sections.append(_ip_profile(cur, job_id, ip))
                for port in ports:
                    sections.append(_port_profile(cur, job_id, port))

                for keywords, builder in KEYWORD_SECTIONS:
                    if words & keywords:
                        sections.append(builder(cur, job_id))

        return "\n\n".join("\n".join(s) for s in sections)

    except Exception:
        logger.exception("SQL context build failed for job %s", job_id)
        return "Exact database aggregates are unavailable for this question."
