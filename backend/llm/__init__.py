"""LLM adapters: local Ollama (red team), remote Gemini (supervisor — see gemini_client)."""

from backend.llm.ollama_client import (
    call_ollama,
    call_ollama_json,
    check_ollama_available,
)

__all__ = [
    "call_ollama",
    "call_ollama_json",
    "check_ollama_available",
]
