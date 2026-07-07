import os

from mcp_firewall.judge.base import JudgeLLM

from mcp_firewall.judge.gemini import GeminiJudge

from mcp_firewall.judge.local_ollama import OllamaJudge



def get_judge() -> JudgeLLM:

    provider = os.getenv('JUDGE_PROVIDER', 'gemini').lower()

    if provider == 'gemini':

        return GeminiJudge()

    elif provider == 'ollama':

        return OllamaJudge()

    else:

        raise ValueError(f"Unsupported configuration JUDGE_PROVIDER: '{provider}'. Supported values: 'gemini', 'ollama'.")
