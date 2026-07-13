"""PacketIQ HTTP API.

Analysis runs as a background job: POST /api/analyze/* returns a job_id
immediately, the frontend polls GET /api/jobs/{id} for stage progress, then
fetches GET /api/jobs/{id}/result. Chat answers stream over SSE.
"""

import json
import logging
import shutil
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from backend.config import (
    ALLOWED_PCAP_EXTENSIONS,
    CORS_ORIGINS,
    PCAP_DIR,
    setup_logging,
)
from backend.db import jobs
from backend.ollama.service import analyze_evidence_stream
from backend.pipeline import PipelineError, create_analysis_job, run_job
from backend.rag.pipeline import query_rag_context
from backend.rag.sql_context import build_sql_context

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="PacketIQ API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzePathRequest(BaseModel):
    path: str


class AskRequest(BaseModel):
    job_id: str
    question: str


def safe_pcap_path(name: str) -> Path:
    """Resolve a user-supplied PCAP name inside PCAP_DIR, rejecting traversal."""
    filename = Path(name).name
    if not filename or filename != name.strip():
        raise HTTPException(status_code=400, detail="Invalid PCAP filename")
    if Path(filename).suffix.lower() not in ALLOWED_PCAP_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type; expected one of {sorted(ALLOWED_PCAP_EXTENSIONS)}",
        )
    return PCAP_DIR / filename


def list_pcap_files() -> list[Path]:
    if not PCAP_DIR.exists():
        return []
    pcaps: list[Path] = []
    for ext in ALLOWED_PCAP_EXTENSIONS:
        pcaps.extend(PCAP_DIR.glob(f"*{ext}"))
    return sorted(pcaps)


def start_analysis(pcap_path: Path, background_tasks: BackgroundTasks) -> dict:
    try:
        job_id = create_analysis_job(pcap_path)
    except PipelineError as e:
        raise HTTPException(status_code=500, detail=str(e))

    background_tasks.add_task(run_job, job_id, pcap_path)
    logger.info("Queued job %s for %s", job_id, pcap_path.name)
    return {"job_id": job_id, "pcap": pcap_path.name, "status": "queued"}


# ─── PCAPs & analysis ─────────────────────────────────────────────────────────

@app.get("/api/pcaps")
def list_pcaps():
    return [p.name for p in list_pcap_files()]


@app.post("/api/analyze/upload")
async def analyze_upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename in upload")

    pcap_path = safe_pcap_path(file.filename)
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    with open(pcap_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    logger.info("Received upload %s (%d bytes)", pcap_path.name, pcap_path.stat().st_size)
    return start_analysis(pcap_path, background_tasks)


@app.post("/api/analyze/path")
def analyze_path(req: AnalyzePathRequest, background_tasks: BackgroundTasks):
    pcap_path = safe_pcap_path(req.path)
    if not pcap_path.exists():
        raise HTTPException(status_code=404, detail=f"PCAP not found: {pcap_path.name}")
    return start_analysis(pcap_path, background_tasks)


# ─── Jobs ─────────────────────────────────────────────────────────────────────

@app.get("/api/jobs")
def list_jobs(limit: int = 10):
    return jobs.list_jobs(limit=min(limit, 50))


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = jobs.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/api/jobs/{job_id}/result")
def get_job_result(job_id: str):
    result = jobs.get_job_result(job_id)
    if result is None:
        job = jobs.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        raise HTTPException(status_code=409, detail=f"Job is {job['status']}, not completed")
    return result


@app.get("/api/jobs/{job_id}/connections")
def get_job_connections(
    job_id: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    conn_state: str | None = None,
    limit: int = 100,
    offset: int = 0,
):
    if jobs.get_job(job_id) is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs.query_connections(
        job_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        conn_state=conn_state,
        limit=limit,
        offset=offset,
    )


@app.get("/api/jobs/{job_id}/dns")
def get_job_dns(job_id: str, search: str | None = None, limit: int = 100, offset: int = 0):
    if jobs.get_job(job_id) is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs.query_dns(job_id, search=search, limit=limit, offset=offset)


@app.get("/api/jobs/{job_id}/http")
def get_job_http(job_id: str, search: str | None = None, limit: int = 100, offset: int = 0):
    if jobs.get_job(job_id) is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs.query_http(job_id, search=search, limit=limit, offset=offset)


@app.get("/api/jobs/{job_id}/tls")
def get_job_tls(job_id: str, search: str | None = None, limit: int = 100, offset: int = 0):
    if jobs.get_job(job_id) is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs.query_tls(job_id, search=search, limit=limit, offset=offset)


# ─── Chat ─────────────────────────────────────────────────────────────────────

@app.post("/api/ask")
def ask(req: AskRequest):
    evidence = jobs.get_evidence(req.job_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Job not found or not completed")

    # Retrieval happens before streaming starts so failures return real errors.
    try:
        sql_context = build_sql_context(req.job_id, req.question)
        rag_context = query_rag_context(req.job_id, req.question)
    except Exception as e:
        logger.exception("Retrieval failed for job %s", req.job_id)
        raise HTTPException(status_code=500, detail=f"Retrieval failed: {e}")

    def event_stream():
        try:
            for fragment in analyze_evidence_stream(
                req.question, evidence, rag_context, sql_context
            ):
                yield f"data: {json.dumps({'token': fragment})}\n\n"
            yield f"data: {json.dumps({'done': True})}\n\n"
        except Exception as e:
            logger.exception("LLM stream failed for job %s", req.job_id)
            yield f"data: {json.dumps({'error': f'AI query failed: {e}'})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
