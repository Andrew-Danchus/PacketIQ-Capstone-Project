from pathlib import Path
from typing import Optional

from langchain_community.vectorstores import FAISS

from .chunker import build_chunks_from_logs, chunk_detection_alerts
from .vectorstore import build_vectorstore
from .retriever import retrieve_relevant_chunks


def build_rag_index(log_dir: Path, detection_results: Optional[dict] = None) -> Optional[FAISS]:
    """
    Build and return a FAISS vectorstore from Zeek logs and optional detection results.
    Call this immediately after PCAP selection / Zeek parsing.
    Returns None if no log data is available.
    """
    print("\nIndexing Zeek logs for RAG retrieval...")

    chunks = build_chunks_from_logs(log_dir)

    if detection_results:
        detection_chunks = chunk_detection_alerts(detection_results)
        chunks.extend(detection_chunks)
        print(f"  {len(detection_chunks)} detection alert(s) indexed.")

    if not chunks:
        print("  No Zeek log data available for indexing.")
        return None

    print(f"  {len(chunks)} total records indexed.")
    return build_vectorstore(chunks)


def query_rag_context(vectorstore: Optional[FAISS], question: str) -> str:
    """
    Retrieve the top-k most relevant chunks from a pre-built vectorstore and
    return a numbered context string ready to be injected into the Ollama prompt.
    """
    if vectorstore is None:
        return "No Zeek log data available for retrieval."

    relevant_chunks = retrieve_relevant_chunks(vectorstore, question)
    context_lines = [f"{i + 1}. {chunk}" for i, chunk in enumerate(relevant_chunks)]
    return "\n".join(context_lines)


def build_rag_context(log_dir: Path, question: str, detection_results: Optional[dict] = None) -> str:
    """Convenience wrapper: build index then query in one call."""
    vectorstore = build_rag_index(log_dir, detection_results)
    return query_rag_context(vectorstore, question)
