def build_analysis_prompt(question: str, evidence: str) -> str:
    return f"""
You are a network forensics analyst.

User Question:
{question}

Zeek Evidence:
{evidence}

Instructions:
1. Answer the user's question directly and specifically.
2. Use only the evidence provided.
3. If the evidence supports a recommendation, explain why.
4. If the evidence is insufficient to answer confidently, say exactly what is missing.
5. Be concise but useful.
""".strip()