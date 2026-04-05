from typing import List

from langchain_ollama import OllamaEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document

EMBEDDING_MODEL = "nomic-embed-text"
OLLAMA_BASE_URL = "http://localhost:11434"


def build_vectorstore(chunks: List[str]) -> FAISS:
    """
    Embed a list of text chunks using nomic-embed-text via Ollama
    and store them in a local FAISS vector index.
    """
    embeddings = OllamaEmbeddings(
        model=EMBEDDING_MODEL,
        base_url=OLLAMA_BASE_URL
    )

    documents = [Document(page_content=chunk) for chunk in chunks]
    vectorstore = FAISS.from_documents(documents, embeddings)

    return vectorstore
