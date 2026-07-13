"""RAG index build and retrieval over pgvector."""

import logging

import psycopg
import requests
from psycopg.rows import dict_row

from backend.config import DATABASE_URL, OLLAMA_BASE_URL, OLLAMA_EMBED_MODEL
from backend.rag.chunker import (
    aggregate_conn_to_chunk,
    connection_to_chunk,
    detection_to_chunk,
    dns_to_chunk,
    http_to_chunk,
    tls_to_chunk,
)

logger = logging.getLogger(__name__)

EMBED_BATCH_SIZE = 64


def get_conn():
    return psycopg.connect(DATABASE_URL)


def embed_texts(texts: list[str]) -> list[list[float]]:
    """Embed texts in batches via Ollama's /api/embed (array input)."""
    if not texts:
        return []

    all_embeddings: list[list[float]] = []
    for i in range(0, len(texts), EMBED_BATCH_SIZE):
        batch = texts[i:i + EMBED_BATCH_SIZE]
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/embed",
            json={"model": OLLAMA_EMBED_MODEL, "input": batch},
            timeout=300,
        )
        resp.raise_for_status()
        all_embeddings.extend(resp.json()["embeddings"])

    return all_embeddings


def embed_text(text: str) -> list[float]:
    return embed_texts([text])[0]


def vector_literal(vec: list[float]) -> str:
    return "[" + ",".join(str(x) for x in vec) + "]"


def build_rag_index(job_id) -> dict:
    """Embed detection alerts and representative log records for a job.

    Assumes the job's logs AND detection results are already ingested into
    Postgres (see backend.db.ingest_logs).
    """
    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            chunks: list[tuple[str, str]] = []

            # 1. Detection alerts — always fully embedded, no limit
            cur.execute(
                """
                SELECT ts, detection_type, severity, src_ip, dst_ip, dst_port, evidence
                FROM detections
                WHERE job_id = %s
                ORDER BY ts
                """,
                (job_id,),
            )
            chunks.extend(("detections", detection_to_chunk(r)) for r in cur.fetchall())

            # 2. Granular connections involving detected attacker IPs
            cur.execute(
                """
                SELECT ts, src_ip, dst_ip, dst_port, proto, service, duration,
                       orig_bytes, resp_bytes, conn_state
                FROM connections
                WHERE job_id = %s
                AND src_ip IN (SELECT DISTINCT src_ip FROM detections
                               WHERE job_id = %s AND src_ip IS NOT NULL)
                ORDER BY ts
                LIMIT 300
                """,
                (job_id, job_id),
            )
            chunks.extend(("connections", connection_to_chunk(r)) for r in cur.fetchall())

            # 3. Aggregated behavioral summary of all connections
            cur.execute(
                """
                SELECT src_ip, dst_ip, dst_port, proto, service, conn_state,
                       COUNT(*) AS count,
                       MIN(ts) AS first_ts, MAX(ts) AS last_ts
                FROM connections
                WHERE job_id = %s
                GROUP BY src_ip, dst_ip, dst_port, proto, service, conn_state
                ORDER BY count DESC
                LIMIT 200
                """,
                (job_id,),
            )
            chunks.extend(("connections_agg", aggregate_conn_to_chunk(r)) for r in cur.fetchall())

            # 4. DNS events
            cur.execute(
                """
                SELECT ts, src_ip, dst_ip, dst_port, query, rcode, answers
                FROM dns_events
                WHERE job_id = %s
                ORDER BY ts
                LIMIT 500
                """,
                (job_id,),
            )
            chunks.extend(("dns_events", dns_to_chunk(r)) for r in cur.fetchall())

            # 5. HTTP events
            cur.execute(
                """
                SELECT ts, src_ip, dst_ip, method, host, uri, user_agent, status_code
                FROM http_events
                WHERE job_id = %s
                ORDER BY ts
                LIMIT 250
                """,
                (job_id,),
            )
            chunks.extend(("http_events", http_to_chunk(r)) for r in cur.fetchall())

            # 6. TLS events
            cur.execute(
                """
                SELECT ts, src_ip, dst_ip, server_name, cert, version, cipher
                FROM tls_events
                WHERE job_id = %s
                ORDER BY ts
                LIMIT 250
                """,
                (job_id,),
            )
            chunks.extend(("tls_events", tls_to_chunk(r)) for r in cur.fetchall())

            if not chunks:
                logger.warning("No chunks to embed for job %s", job_id)
                return {"status": "ok", "inserted": 0}

            texts = [c[1] for c in chunks]
            logger.info("Embedding %d chunks for job %s", len(texts), job_id)
            embeddings = embed_texts(texts)

            rows = [
                (str(job_id), source, text, vector_literal(embedding))
                for (source, text), embedding in zip(chunks, embeddings)
            ]

            cur.execute("DELETE FROM rag_chunks WHERE job_id = %s", (job_id,))
            cur.executemany(
                """
                INSERT INTO rag_chunks (job_id, source, chunk_text, embedding)
                VALUES (%s, %s, %s, %s)
                """,
                rows,
            )

        conn.commit()

    logger.info("Inserted %d RAG chunks for job %s", len(rows), job_id)
    return {"status": "ok", "inserted": len(rows)}


def query_rag_context(job_id, question: str, top_k: int = 8) -> str:
    """Return the most relevant chunks for a question, formatted as plain text."""
    question_embedding = vector_literal(embed_text(question))

    with get_conn() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT source, chunk_text
                FROM rag_chunks
                WHERE job_id = %s
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                (job_id, question_embedding, top_k),
            )
            rows = cur.fetchall()

    if not rows:
        return "No log records retrieved for this question."

    return "\n".join(f"[{row['source']}] {row['chunk_text']}" for row in rows)
