"""End-to-end analysis pipeline: Zeek → detections → DB ingest → RAG index → stats.

Shared by the HTTP API (backend.api, as a background task) and the CLI
(backend.cli). Job status/stage/results are persisted via backend.db.jobs so
progress can be polled and sessions reloaded.
"""

import logging
import time
import uuid
from pathlib import Path

from backend.config import DATABASE_URL, OUTPUT_DIR
from backend.db import jobs
from backend.db.ingest_logs import ingest_job_logs
from backend.detection.detection import run_detections
from backend.parsing.summarize import compute_stats, render_evidence
from backend.parsing.zeek_runner import get_log_dir, run_zeek_on_pcap
from backend.rag.pipeline import build_rag_index

logger = logging.getLogger(__name__)


class PipelineError(RuntimeError):
    pass


def create_analysis_job(pcap_path: Path) -> str:
    """Register a queued job for a PCAP and return its id."""
    if not DATABASE_URL:
        raise PipelineError("DATABASE_URL is not set; cannot create jobs.")

    job_id = str(uuid.uuid4())
    jobs.create_job(job_id, pcap_path.name, pcap_path.stat().st_size)
    return job_id


def run_job(job_id: str, pcap_path: Path) -> dict | None:
    """Execute the pipeline for a queued job, recording stage transitions.

    Returns the result payload on success; marks the job failed and returns
    None on error (exceptions are captured into the job row so pollers see
    them).
    """
    timings: dict[str, float] = {}
    total_start = time.perf_counter()

    def timed(stage: str, func, *args, **kwargs):
        jobs.set_stage(job_id, stage)
        start = time.perf_counter()
        result = func(*args, **kwargs)
        timings[stage] = round(time.perf_counter() - start, 2)
        return result

    try:
        # 1. Zeek parsing
        log_dir = get_log_dir(pcap_path)
        timed("zeek", run_zeek_on_pcap, pcap_path, log_dir)

        # 2. Detections
        conn_log_path = log_dir / "conn.log"
        detection_results = {"port_scans": [], "ddos": [], "brute_force": []}
        if conn_log_path.exists():
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            detection_results = timed(
                "detection",
                run_detections,
                str(conn_log_path),
                str(OUTPUT_DIR / "detection.json"),
            )
        else:
            logger.warning("No conn.log produced for %s; skipping detections", pcap_path.name)

        # 3. DB ingestion (logs + detection alerts)
        timed(
            "ingest",
            ingest_job_logs,
            job_id=job_id,
            log_dir=log_dir,
            dsn=DATABASE_URL,
            detection_results=detection_results,
        )

        # 4. RAG index
        timed("rag_index", build_rag_index, job_id)

        # 5. Structured stats + prose evidence for LLM context
        stats = timed("summary", compute_stats, log_dir)
        evidence = render_evidence(stats)

        timings["total"] = round(time.perf_counter() - total_start, 2)
        jobs.complete_job(job_id, stats, evidence, timings)
        logger.info("Pipeline complete for %s: %s", pcap_path.name, timings)

        return {
            "job_id": job_id,
            "pcap": pcap_path.name,
            "stats": stats,
            "evidence": evidence,
            "detections": detection_results,
            "timings": timings,
        }

    except Exception as e:
        logger.exception("Pipeline failed for job %s (%s)", job_id, pcap_path.name)
        try:
            jobs.fail_job(job_id, str(e))
        except Exception:
            logger.exception("Could not mark job %s as failed", job_id)
        return None


def analyze_pcap(pcap_path: Path) -> dict:
    """Synchronous convenience wrapper: create a job, run it, return the result."""
    job_id = create_analysis_job(pcap_path)
    result = run_job(job_id, pcap_path)
    if result is None:
        job = jobs.get_job(job_id)
        raise PipelineError(job["error_message"] if job else "Analysis failed")
    return result
