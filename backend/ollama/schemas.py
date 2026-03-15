from pydantic import BaseModel


class ExplainRequest(BaseModel):
    alert_type: str
    evidence: str


class ExplainResponse(BaseModel):
    answer: str