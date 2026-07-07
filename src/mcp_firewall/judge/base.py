from typing import Protocol, List

from pydantic import BaseModel, Field



class Verdict(BaseModel):

    risk_tier: str = Field(description="Safety risk tier evaluation of the tool payload. Allowed values: 'low', 'medium', 'high'")

    reasoning: str = Field(description='CoT reasoning explaining why the payload constitutes a specific risk level.')

    flags: List[str] = Field(default_factory=list, description="Security signals detected: 'prompt_injection', 'exfiltration', 'destructive_action_run', 'path_traversal'")

    score: float = Field(description='Calculated danger score float ranging from 0.0 (safe) to 1.0 (highly critical).')



class JudgeLLM(Protocol):



    async def classify(self, tool_name: str, arguments: dict) -> Verdict:

        ...
