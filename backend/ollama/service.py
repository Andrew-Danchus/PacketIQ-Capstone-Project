from .client import OllamaClient
from .prompt_builder import build_analysis_prompt

client = OllamaClient()

def analyze_evidence(question: str, evidence: str) -> str:
    prompt = build_analysis_prompt(question, evidence)

    messages = [
        {
            "role": "system",
            "content": (
                "You are a cybersecurity analyst specializing in network forensics. "
                "Answer the user's question directly using only the provided Zeek evidence."
            )
        },
        {
            "role": "user",
            "content": prompt
        }
    ]

    result = client.chat(messages, stream=False)
    return result["message"]["content"]