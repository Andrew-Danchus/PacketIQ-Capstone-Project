from .client import OllamaClient
from .prompt_builder import build_analysis_messages

client = OllamaClient()


def analyze_evidence(
    question: str, summary: str, rag_context: str, sql_context: str = ""
) -> str:
    messages = build_analysis_messages(question, summary, rag_context, sql_context)
    return client.chat(messages)


def analyze_evidence_stream(
    question: str, summary: str, rag_context: str, sql_context: str = ""
):
    """Yield answer fragments as the model generates them."""
    messages = build_analysis_messages(question, summary, rag_context, sql_context)
    yield from client.chat_stream(messages)
