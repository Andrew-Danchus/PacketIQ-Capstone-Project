"""Ingest Zeek JSON logs and detection results into PostgreSQL."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import psycopg

from backend.parsing.zeek_logs import load_json_log

logger = logging.getLogger(__name__)


def parse_ts(value):
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


def parse_int(value):
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_float(value):
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def insert_connections(conn, job_id, records):
    rows = [
        (
            job_id,
            parse_ts(r.get("ts")),
            r.get("id.orig_h"),
            parse_int(r.get("id.orig_p")),
            r.get("id.resp_h"),
            parse_int(r.get("id.resp_p")),
            r.get("proto"),
            r.get("service"),
            parse_float(r.get("duration")),
            parse_int(r.get("orig_bytes")),
            parse_int(r.get("resp_bytes")),
            r.get("conn_state"),
        )
        for r in records
    ]
    if not rows:
        return

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO connections
            (job_id, ts, src_ip, src_port, dst_ip, dst_port,
             proto, service, duration, orig_bytes, resp_bytes, conn_state)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


def insert_dns(conn, job_id, records):
    rows = [
        (
            job_id,
            parse_ts(r.get("ts")),
            r.get("id.orig_h"),
            parse_int(r.get("id.orig_p")),
            r.get("id.resp_h"),
            parse_int(r.get("id.resp_p")),
            r.get("proto"),
            r.get("query"),
            parse_int(r.get("qtype")),
            parse_int(r.get("rcode")),
            json.dumps(r.get("answers")) if r.get("answers") is not None else None,
        )
        for r in records
    ]
    if not rows:
        return

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO dns_events
            (job_id, ts, src_ip, src_port, dst_ip, dst_port,
             proto, query, qtype, rcode, answers)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


def insert_http(conn, job_id, records):
    rows = [
        (
            job_id,
            parse_ts(r.get("ts")),
            r.get("id.orig_h"),
            parse_int(r.get("id.orig_p")),
            r.get("id.resp_h"),
            parse_int(r.get("id.resp_p")),
            r.get("proto"),
            r.get("method"),
            r.get("host"),
            r.get("uri"),
            r.get("user_agent"),
            parse_int(r.get("status_code")),
        )
        for r in records
    ]
    if not rows:
        return

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO http_events
            (job_id, ts, src_ip, src_port, dst_ip, dst_port,
             proto, method, host, uri, user_agent, status_code)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


def insert_tls(conn, job_id, records):
    rows = [
        (
            job_id,
            parse_ts(r.get("ts")),
            r.get("id.orig_h"),
            r.get("id.resp_h"),
            r.get("server_name"),
            r.get("subject"),
            r.get("version"),
            r.get("cipher"),
        )
        for r in records
    ]
    if not rows:
        return

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO tls_events
            (job_id, ts, src_ip, dst_ip, server_name, cert, version, cipher)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


def insert_zeek_notices(conn, job_id, records):
    """Zeek notice.log entries are stored as detections of type zeek_notice
    so they surface alongside PacketIQ's own detections."""
    rows = [
        (
            job_id,
            parse_ts(r.get("ts")) or datetime.now(tz=timezone.utc),
            f"zeek_notice:{r.get('note', 'unknown')}",
            "medium",
            r.get("src"),
            r.get("dst"),
            parse_int(r.get("p")),
            json.dumps(r),
        )
        for r in records
    ]
    if not rows:
        return

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO detections
            (job_id, ts, detection_type, severity, src_ip, dst_ip, dst_port, evidence)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )


def insert_detections(conn, job_id, detection_results: dict):
    """Persist run_detections() output so the RAG index and API can query it.

    This was the core missing link in the original implementation: detection
    alerts were shown in the UI but never stored, so the AI never saw them.
    """
    rows = []
    for alert in (
        detection_results.get("port_scans", [])
        + detection_results.get("ddos", [])
        + detection_results.get("brute_force", [])
    ):
        rows.append(
            (
                job_id,
                parse_ts(alert.get("first_seen_ts")) or datetime.now(tz=timezone.utc),
                alert.get("type", "unknown"),
                alert.get("severity", "medium"),
                alert.get("src_ip"),
                alert.get("dst_ip"),
                parse_int(alert.get("dst_port")),
                json.dumps(alert),
            )
        )
    if not rows:
        return

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO detections
            (job_id, ts, detection_type, severity, src_ip, dst_ip, dst_port, evidence)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            rows,
        )
    logger.info("Inserted %d detection alerts for job %s", len(rows), job_id)


def ingest_job_logs(job_id, log_dir, dsn, detection_results: dict | None = None):
    """Ingest all Zeek logs and detection alerts for an existing job row.

    Job lifecycle (create/stage/complete/fail) is owned by backend.db.jobs.
    """
    log_dir = Path(log_dir)

    with psycopg.connect(dsn) as conn:
        insert_connections(conn, job_id, load_json_log(log_dir / "conn.log"))
        insert_dns(conn, job_id, load_json_log(log_dir / "dns.log"))
        insert_http(conn, job_id, load_json_log(log_dir / "http.log"))
        insert_tls(conn, job_id, load_json_log(log_dir / "ssl.log"))
        insert_zeek_notices(conn, job_id, load_json_log(log_dir / "notice.log"))

        if detection_results:
            insert_detections(conn, job_id, detection_results)

        conn.commit()

    logger.info("Ingestion complete for job %s", job_id)
