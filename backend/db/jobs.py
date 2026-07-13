"""Job lifecycle and result storage in Postgres.

A job is one analysis of one PCAP. Results (stats, evidence, timings) are
stored on the job row so sessions survive backend restarts and can be
reloaded from any browser.
"""

import json
import logging

import psycopg
from psycopg.rows import dict_row

from backend.config import DATABASE_URL

logger = logging.getLogger(__name__)

# Maps detections.detection_type to the result-payload keys the UI expects.
DETECTION_TYPE_KEYS = {
    "port_scan": "port_scans",
    "ddos": "ddos",
    "brute_force": "brute_force",
}


def get_conn():
    return psycopg.connect(DATABASE_URL)


def create_job(job_id: str, filename: str, file_size_bytes: int) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO jobs (id, filename, file_size_bytes, status)
            VALUES (%s, %s, %s, 'queued')
            """,
            (job_id, filename, file_size_bytes),
        )


def set_stage(job_id: str, stage: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE jobs SET status = 'processing', stage = %s WHERE id = %s",
            (stage, job_id),
        )


def complete_job(job_id: str, stats: dict, evidence: str, timings: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE jobs
            SET status = 'completed', stage = NULL,
                stats = %s, evidence = %s, timings = %s
            WHERE id = %s
            """,
            (json.dumps(stats), evidence, json.dumps(timings), job_id),
        )


def fail_job(job_id: str, error: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE jobs SET status = 'failed', stage = NULL, error_message = %s WHERE id = %s",
            (error[:2000], job_id),
        )


def get_job(job_id: str) -> dict | None:
    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT id, filename, created_at, status, stage,
                       file_size_bytes, error_message, timings
                FROM jobs WHERE id = %s
                """,
                (job_id,),
            )
            row = cur.fetchone()
    if row:
        row["id"] = str(row["id"])
        row["created_at"] = row["created_at"].isoformat()
    return row


def list_jobs(limit: int = 10) -> list[dict]:
    """Recent completed jobs, newest first — one entry per filename."""
    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT DISTINCT ON (filename)
                       id, filename, created_at, file_size_bytes
                FROM jobs
                WHERE status = 'completed'
                ORDER BY filename, created_at DESC
                """,
            )
            rows = cur.fetchall()

    rows.sort(key=lambda r: r["created_at"], reverse=True)
    for row in rows:
        row["id"] = str(row["id"])
        row["created_at"] = row["created_at"].isoformat()
    return rows[:limit]


def get_detections(job_id: str) -> dict:
    """Rebuild the detections payload from stored alert JSON."""
    results = {key: [] for key in DETECTION_TYPE_KEYS.values()}

    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT detection_type, evidence
                FROM detections
                WHERE job_id = %s AND detection_type = ANY(%s)
                ORDER BY ts
                """,
                (job_id, list(DETECTION_TYPE_KEYS)),
            )
            for row in cur.fetchall():
                key = DETECTION_TYPE_KEYS[row["detection_type"]]
                evidence = row["evidence"]
                if isinstance(evidence, str):
                    evidence = json.loads(evidence)
                results[key].append(evidence)

    return results


def get_job_result(job_id: str) -> dict | None:
    """Full result payload for a completed job, or None."""
    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT id, filename, status, stats, evidence, timings
                FROM jobs WHERE id = %s AND status = 'completed'
                """,
                (job_id,),
            )
            row = cur.fetchone()

    if not row:
        return None

    return {
        "job_id": str(row["id"]),
        "pcap": row["filename"],
        "stats": row["stats"],
        "evidence": row["evidence"],
        "detections": get_detections(job_id),
        "timings": row["timings"],
    }


def get_evidence(job_id: str) -> str | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT evidence FROM jobs WHERE id = %s", (job_id,))
            row = cur.fetchone()
    return row[0] if row else None


def query_connections(
    job_id: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    conn_state: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Filtered, paged slice of the connections table for a job."""
    clauses = ["job_id = %s"]
    params: list = [job_id]

    if src_ip:
        clauses.append("src_ip = %s")
        params.append(src_ip)
    if dst_ip:
        clauses.append("dst_ip = %s")
        params.append(dst_ip)
    if dst_port is not None:
        clauses.append("dst_port = %s")
        params.append(dst_port)
    if conn_state:
        clauses.append("conn_state = %s")
        params.append(conn_state)

    where = " AND ".join(clauses)
    limit = max(1, min(limit, 500))

    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SELECT COUNT(*) AS total FROM connections WHERE {where}", params)
            total = cur.fetchone()["total"]

            cur.execute(
                f"""
                SELECT ts, src_ip, src_port, dst_ip, dst_port, proto, service,
                       duration, orig_bytes, resp_bytes, conn_state
                FROM connections
                WHERE {where}
                ORDER BY ts
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            rows = cur.fetchall()

    for row in rows:
        row["ts"] = row["ts"].isoformat() if row["ts"] else None
        row["src_ip"] = str(row["src_ip"]) if row["src_ip"] else None
        row["dst_ip"] = str(row["dst_ip"]) if row["dst_ip"] else None

    return {"total": total, "limit": limit, "offset": offset, "connections": rows}


def _normalize_row(row: dict) -> dict:
    """Stringify INET columns and ISO-format timestamps for JSON output."""
    for key in ("src_ip", "dst_ip"):
        if key in row and row[key] is not None:
            row[key] = str(row[key])
    if row.get("ts") is not None and hasattr(row["ts"], "isoformat"):
        row["ts"] = row["ts"].isoformat()
    return row


def _query_events(
    table: str,
    columns: str,
    result_key: str,
    job_id: str,
    filters: dict[str, object],
    search_columns: list[str],
    search: str | None,
    limit: int,
    offset: int,
) -> dict:
    """Generic filtered/searched/paged query over a per-job event table."""
    clauses = ["job_id = %s"]
    params: list = [job_id]

    for column, value in filters.items():
        if value is not None:
            clauses.append(f"{column} = %s")
            params.append(value)

    if search and search_columns:
        ors = " OR ".join(f"{col}::text ILIKE %s" for col in search_columns)
        clauses.append(f"({ors})")
        params.extend([f"%{search}%"] * len(search_columns))

    where = " AND ".join(clauses)
    limit = max(1, min(limit, 500))

    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SELECT COUNT(*) AS total FROM {table} WHERE {where}", params)
            total = cur.fetchone()["total"]

            cur.execute(
                f"SELECT {columns} FROM {table} WHERE {where} "
                f"ORDER BY ts LIMIT %s OFFSET %s",
                params + [limit, offset],
            )
            rows = [_normalize_row(r) for r in cur.fetchall()]

    return {"total": total, "limit": limit, "offset": offset, result_key: rows}


def query_dns(job_id, search=None, limit=100, offset=0) -> dict:
    return _query_events(
        "dns_events",
        "ts, src_ip, dst_ip, dst_port, query, qtype, rcode, answers",
        "dns",
        job_id,
        {},
        ["query", "answers"],
        search,
        limit,
        offset,
    )


def query_http(job_id, search=None, limit=100, offset=0) -> dict:
    return _query_events(
        "http_events",
        "ts, src_ip, dst_ip, method, host, uri, user_agent, status_code",
        "http",
        job_id,
        {},
        ["host", "uri", "user_agent"],
        search,
        limit,
        offset,
    )


def query_tls(job_id, search=None, limit=100, offset=0) -> dict:
    return _query_events(
        "tls_events",
        "ts, src_ip, dst_ip, server_name, version, cipher, cert",
        "tls",
        job_id,
        {},
        ["server_name", "version", "cipher"],
        search,
        limit,
        offset,
    )
