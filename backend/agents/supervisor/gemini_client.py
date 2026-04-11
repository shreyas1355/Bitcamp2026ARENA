"""
gemini_client.py — Gemini API wrapper.

TODO (Dev A, Phase 5): Implement this file.

Responsibilities:
- configure_gemini(api_key): called once at startup
- call_gemini(system_prompt, user_prompt): wraps genai call with retry + backoff
"""

import time
from backend.config import GEMINI_MODEL, GEMINI_MAX_RETRIES, GEMINI_RETRY_DELAY_S

_configured = False


def configure_gemini(api_key: str) -> None:
    global _configured
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        _configured = True
        print(f"[GEMINI] Configured with model {GEMINI_MODEL}")
    except Exception as e:
        print(f"[GEMINI] Configuration failed: {e}")


def call_gemini(system_prompt: str, user_prompt: str) -> str:
    """
    TODO (Dev A): Implement with retry logic.

    Calls Gemini 1.5 Flash with the given prompts.
    Returns response text as string.
    Retries up to GEMINI_MAX_RETRIES times on ResourceExhausted (429).
    Uses exponential backoff starting at GEMINI_RETRY_DELAY_S seconds.
    Raises RuntimeError after all retries exhausted.
    """
    if not _configured:
        raise RuntimeError("Gemini not configured. Call configure_gemini() first.")

    # STUB — replace with real implementation
    return '{"risk_score": 0.5, "vulnerabilities": [], "mitigations": ["STUB — implement gemini_client.py"], "next_episode_strategy": "Continue testing", "episode_summary": "Stub episode summary.", "token_count": 0}'
