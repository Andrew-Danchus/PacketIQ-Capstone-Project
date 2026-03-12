from pathlib import Path
from typing import Optional

from .chunker import build_chunks_from_logs, chunk_detection_alerts
from .vectorstore import build_vectorstore
from .retriever import retrieve_relevant_chunks


def build_rag_context(log_dir: Path, question: str, detection_results: Optional[dict] = None) -> str:
    """
    Full RAG pipeline:
      1. Parse Zeek logs into natural language text chunks
      2. Append detection alert chunks (port scan, DDoS, brute force) if provided
      3. Embed all chunks and index them into a FAISS vector store
      4. Embed the user's question and retrieve the top-k most relevant chunks
      5. Return a numbered context string ready to be injected into the Ollama prompt
    """
    print("\nIndexing Zeek logs for RAG retrieval...")

    chunks = build_chunks_from_logs(log_dir)

    if detection_results:
        detection_chunks = chunk_detection_alerts(detection_results)
        chunks.extend(detection_chunks)
        print(f"  {len(detection_chunks)} detection alert(s) indexed.")

    if not chunks:
        return "No Zeek log data available for retrieval."

    print(f"  {len(chunks)} total records indexed.")

    vectorstore = build_vectorstore(chunks)
    relevant_chunks = retrieve_relevant_chunks(vectorstore, question)

    context_lines = [f"{i + 1}. {chunk}" for i, chunk in enumerate(relevant_chunks)]
    return "\n".join(context_lines)
