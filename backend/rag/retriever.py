from typing import List

from langchain_community.vectorstores import FAISS

TOP_K = 10


def retrieve_relevant_chunks(vectorstore: FAISS, question: str, k: int = TOP_K) -> List[str]:
    """
    Embed the user's question and retrieve the top-k most semantically
    similar chunks from the FAISS vector store using cosine similarity.
    """
    results = vectorstore.similarity_search(question, k=k)
    return [doc.page_content for doc in results]
