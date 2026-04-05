"""
api.py — FastAPI server for PacketIQ
Exposes three endpoints consumed by the React frontend:

  GET  /api/pcaps   — list available PCAP files
  POST /api/analyze — run Zeek + detection + RAG on a PCAP
  POST /api/ask     — query the AI with a follow-up question

Run with:
  uvicorn api:app --host 0.0.0.0 --port 5000 --reload
"""

from pathlib import Path
from typing import Optional
import shutil

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

# ── Single-session in-memory state ────────────────────────────────────────────
_vectorstore = None                      # FAISS index from last /api/analyze
_current_log_dir: Optional[Path] = None  # log directory for that session


# ── Schemas ───────────────────────────────────────────────────────────────────

class AskRequest(BaseModel):
    question: str
    evidence: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/pcaps")
def list_pcaps():
    """Return a sorted list of PCAP filenames from the pcaps/ directory."""
    return [p.name for p in list_pcap_files()]


@app.post("/api/analyze")
async def analyze(request: Request):
    """
    Accept either:
      • multipart/form-data  with field 'file'  (file picker / drag-and-drop)
      • application/json     with field 'path'  (filename from sidebar click)

    Runs Zeek, threat detection, and builds the RAG index.
    Returns { evidence, pcap }.
    """
    global _vectorstore, _current_log_dir

    content_type = request.headers.get("content-type", "")

    # ── Resolve the PCAP path ─────────────────────────────────────────────────
    if "multipart/form-data" in content_type:
        form = await request.form()
        upload = form.get("file")
        if upload is None:
            raise HTTPException(status_code=400, detail="No file field in form data")

        PCAP_DIR.mkdir(parents=True, exist_ok=True)
        pcap_path = PCAP_DIR / upload.filename
        with open(pcap_path, "wb") as f:
            shutil.copyfileobj(upload.file, f)

    elif "application/json" in content_type:
        body = await request.json()
        pcap_name = body.get("path")
        if not pcap_name:
            raise HTTPException(status_code=400, detail="No 'path' field in JSON body")

        pcap_path = PCAP_DIR / pcap_name
        if not pcap_path.exists():
            raise HTTPException(status_code=404, detail=f"PCAP not found: {pcap_name}")

    else:
        raise HTTPException(status_code=415, detail="Unsupported content type")

    # ── Zeek ──────────────────────────────────────────────────────────────────
    log_dir = get_log_dir(pcap_path)
    success = run_zeek_on_pcap(pcap_path, log_dir)
    if not success:
        raise HTTPException(status_code=500, detail="Zeek parsing failed")

    # ── Detection ─────────────────────────────────────────────────────────────
    detection_results = None
    conn_log_path = log_dir / "conn.log"
    if conn_log_path.exists():
        try:
            output_path = PROJECT_ROOT / "output" / "detection.json"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            detection_results = run_detections(str(conn_log_path), str(output_path))
        except Exception:
            pass  # detection is best-effort; don't block the response

    # ── RAG index ─────────────────────────────────────────────────────────────
    _vectorstore = build_rag_index(log_dir, detection_results)
    _current_log_dir = log_dir

    # ── Summary ───────────────────────────────────────────────────────────────
    evidence = summarize_logs(log_dir)
    return {"evidence": evidence, "pcap": pcap_path.name}


@app.post("/api/ask")
async def ask(req: AskRequest):
    """
    Query the AI with a follow-up question.
    Uses the RAG index built during the most recent /api/analyze call.
    Returns { answer }.
    """
    rag_context = query_rag_context(_vectorstore, req.question)
    try:
        answer = analyze_evidence(req.question, req.evidence, rag_context)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"answer": answer}


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
