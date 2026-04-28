from pathlib import Path
from typing import Optional
import os
import shutil
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from main import (
    get_log_dir,
    run_zeek_on_pcap,
    summarize_logs,
    list_pcap_files,
    PROJECT_ROOT,
    PCAP_DIR,
)
from backend.db.ingest_logs import ingest_job_logs
from backend.ollama.service import analyze_evidence
from backend.rag.pipeline import build_rag_index, query_rag_context
from backend.detection.detection import run_detections


app = FastAPI(title="PacketIQ API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_current_job_id: Optional[str] = None
_current_log_dir: Optional[Path] = None
_current_evidence: Optional[str] = None


class AskRequest(BaseModel):
    question: str
    evidence: str


def ingest_pcap_logs_to_db(pcap_path: Path, log_dir: Path) -> str | None:
    job_id = str(uuid.uuid4())
    dsn = os.getenv("DATABASE_URL")

    print(f"DEBUG: ingest_pcap_logs_to_db called")
    print(f"DEBUG: pcap_path={pcap_path}")
    print(f"DEBUG: log_dir={log_dir}")
    print(f"DEBUG: DATABASE_URL set={bool(dsn)}")
    if dsn:
        print(f"DEBUG: DATABASE_URL={dsn}")

    if not dsn:
        print("DEBUG: DATABASE_URL is missing")
        return None

    try:
        ingest_job_logs(
            job_id=job_id,
            filename=pcap_path.name,
            file_size_bytes=pcap_path.stat().st_size,
            log_dir=log_dir,
            dsn=dsn,
        )
        print(f"DEBUG: DB ingestion succeeded, job_id={job_id}")
        return job_id
    except Exception as e:
        print(f"DEBUG: DB ingestion exception: {e}")
        return None


@app.get("/api/pcaps")
def list_pcaps():
    return [p.name for p in list_pcap_files()]


@app.post("/api/analyze")
async def analyze(request: Request):
    global _current_job_id, _current_log_dir, _current_evidence

    try:
        print("DEBUG: /api/analyze called")
        content_type = request.headers.get("content-type", "")
        print(f"DEBUG: content-type={content_type}")

        # Resolve PCAP path
        if "multipart/form-data" in content_type:
            form = await request.form()
            upload = form.get("file")
            if upload is None:
                raise HTTPException(status_code=400, detail="No file field in form data")

            print(f"DEBUG: uploaded filename={upload.filename}")

            PCAP_DIR.mkdir(parents=True, exist_ok=True)
            pcap_path = PCAP_DIR / upload.filename
            with open(pcap_path, "wb") as f:
                shutil.copyfileobj(upload.file, f)

        elif "application/json" in content_type:
            body = await request.json()
            print(f"DEBUG: json body={body}")

            pcap_name = body.get("path")
            if not pcap_name:
                raise HTTPException(status_code=400, detail="No 'path' field in JSON body")

            pcap_path = PCAP_DIR / pcap_name
            if not pcap_path.exists():
                raise HTTPException(status_code=404, detail=f"PCAP not found: {pcap_name}")

        else:
            raise HTTPException(status_code=415, detail="Unsupported content type")

        print(f"DEBUG: resolved pcap_path={pcap_path}")
        print(f"DEBUG: pcap exists={pcap_path.exists()}")

        # Zeek
        log_dir = get_log_dir(pcap_path)
        print(f"DEBUG: log_dir={log_dir}")
        print("DEBUG: starting Zeek")

        success = run_zeek_on_pcap(pcap_path, log_dir)
        print(f"DEBUG: Zeek success={success}")

        if not success:
            raise HTTPException(status_code=500, detail="Zeek parsing failed")

        # Detection
        detection_results = None
        conn_log_path = log_dir / "conn.log"
        print(f"DEBUG: conn_log_path={conn_log_path}")
        print(f"DEBUG: conn_log exists={conn_log_path.exists()}")

        if conn_log_path.exists():
            try:
                print("DEBUG: starting detections")
                output_path = PROJECT_ROOT / "output" / "detection.json"
                output_path.parent.mkdir(parents=True, exist_ok=True)
                detection_results = run_detections(str(conn_log_path), str(output_path))
                print("DEBUG: detections completed")
            except Exception as e:
                print(f"DEBUG: detection exception: {e}")

        # DB ingestion
        print("DEBUG: starting DB ingestion")
        job_id = ingest_pcap_logs_to_db(pcap_path, log_dir)
        print(f"DEBUG: DB ingestion returned job_id={job_id}")

        if job_id is None:
            raise HTTPException(status_code=500, detail="Database ingestion failed")

        _current_job_id = job_id
        _current_log_dir = log_dir

        # RAG
        print("DEBUG: starting RAG build")
        build_rag_index(job_id, log_dir, detection_results)
        print("DEBUG: RAG build completed")

        # Summary
        print("DEBUG: starting summarization")
        evidence = summarize_logs(log_dir)
        _current_evidence = evidence
        print("DEBUG: summarization completed")

        return {"evidence": evidence, "pcap": pcap_path.name, "detections": detection_results or {}}

    except HTTPException:
        raise
    except Exception as e:
        print(f"DEBUG: /api/analyze exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ask")
async def ask(req: AskRequest):
    try:
        print("DEBUG: /api/ask called")
        print(f"DEBUG: current_job_id={_current_job_id}")
        print(f"DEBUG: question={req.question}")

        if _current_job_id is None:
            raise HTTPException(status_code=400, detail="No analysis has been run yet")

        print("DEBUG: querying RAG context")
        rag_context = query_rag_context(_current_job_id, req.question)
        print("DEBUG: RAG context retrieved")

        print("DEBUG: starting Ollama analysis")
        answer = analyze_evidence(req.question, req.evidence, rag_context)
        print("DEBUG: Ollama analysis completed")

        return {"answer": answer}

    except HTTPException:
        raise
    except Exception as e:
        print(f"DEBUG: /api/ask exception: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)