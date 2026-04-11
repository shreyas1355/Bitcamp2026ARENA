"""
Gemini API wrapper — ONLY call site for generative AI outside tests.
"""

from __future__ import annotations

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


def is_configured() -> bool:
    return _configured


def call_gemini(system_prompt: str, user_prompt: str) -> str:
    """
    Calls Gemini with retries on quota / resource exhaustion.
    Exponential backoff from GEMINI_RETRY_DELAY_S.
    """
    if not _configured:
        raise RuntimeError("Gemini not configured. Call configure_gemini() first.")

    import google.generativeai as genai

    try:
        from google.api_core import exceptions as gexc
    except ImportError:  # pragma: no cover
        gexc = None

    delay = GEMINI_RETRY_DELAY_S
    last_err: Exception | None = None

    for attempt in range(GEMINI_MAX_RETRIES + 1):
        try:
            model = genai.GenerativeModel(
                GEMINI_MODEL,
                system_instruction=system_prompt,
            )
            response = model.generate_content(user_prompt)
            text = getattr(response, "text", None)
            if text:
                return text
            # Blocked or empty — surface as error for retry/fallback
            raise RuntimeError("Gemini returned empty response")
        except Exception as e:
            last_err = e
            retryable = False
            if gexc and isinstance(e, gexc.ResourceExhausted):
                retryable = True
            elif "Resource exhausted" in str(e) or "429" in str(e):
                retryable = True
            if not retryable or attempt >= GEMINI_MAX_RETRIES:
                break
            print(f"[GEMINI] retry {attempt + 1}/{GEMINI_MAX_RETRIES} after {delay:.1f}s: {e}")
            time.sleep(delay)
            delay *= 2.0

    raise RuntimeError(f"Gemini call failed after retries: {last_err}")
