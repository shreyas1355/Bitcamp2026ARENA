"""
ollama_client.py — Local Ollama inference wrapper for red team strategy.

Called every step from strategy.py ONLY. Zero API cost — runs on local hardware.
Primary model: OLLAMA_MODEL (default llama3). Fallback: OLLAMA_FALLBACK_MODEL.

Setup (one-time):
    ollama serve          # start the server (auto-starts on most installs)
    ollama pull llama3    # ~4GB download

RULES (PROMPT_V2 / .cursorrules):
  - Rule 11: called from strategy.py only. Never from blue agents or supervisor.
  - Timeouts / connection failures → RuntimeError so strategy.py can use rule-based fallback.
  - call_ollama_json never blocks the arena on bad JSON — returns _safe_default_decision().

Optional dependency: ``pip install ollama``. If missing, check_ollama_available() is False
and call_ollama raises RuntimeError with install instructions.
"""

from __future__ import annotations

import concurrent.futures
import json
import re
from typing import Any, Mapping

try:
    import ollama as _ollama
except ImportError:  # pragma: no cover - exercised when ollama not installed
    _ollama = None

from backend.config import (
    OLLAMA_FALLBACK_MODEL,
    OLLAMA_MODEL,
    OLLAMA_NUM_PREDICT,
    OLLAMA_PING_TIMEOUT_S,
    OLLAMA_TIMEOUT_S,
)


def _ollama_ready() -> bool:
    return _ollama is not None


def _chat_response_text(response: Any) -> str:
    """Normalize ollama.chat return value (dict-like ChatResponse) to assistant text."""
    if response is None:
        return ""
    if isinstance(response, Mapping):
        msg = response.get("message") or {}
        if isinstance(msg, Mapping):
            return str(msg.get("content", ""))
    msg = getattr(response, "message", None)
    if msg is not None:
        return str(getattr(msg, "content", "") or "")
    return ""


# ── Public API ─────────────────────────────────────────────────────────────────


def call_ollama(prompt: str, model: str | None = None) -> str:
    """
    Calls Ollama synchronously and returns the raw assistant message string.

    Uses ThreadPoolExecutor to enforce OLLAMA_TIMEOUT_S (ollama-python has no
    native timeout on chat).

    Raises:
        RuntimeError — package missing, Ollama not running, model not found, or timeout.
    """
    if not _ollama_ready():
        raise RuntimeError(
            "The Python package 'ollama' is not installed. "
            "Install with: pip install ollama"
        )

    target_model = model or OLLAMA_MODEL
    chat_options = {"num_predict": OLLAMA_NUM_PREDICT}

    def _chat() -> str:
        response = _ollama.chat(
            model=target_model,
            messages=[{"role": "user", "content": prompt}],
            options=chat_options,
        )
        text = _chat_response_text(response)
        if not text and isinstance(response, Mapping):
            # Some versions expose top-level "message" only after normalize
            text = str(response.get("response", "") or "")
        return text

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_chat)
            return future.result(timeout=OLLAMA_TIMEOUT_S)

    except concurrent.futures.TimeoutError:
        raise RuntimeError(
            f"Ollama timed out after {OLLAMA_TIMEOUT_S}s. "
            "Try a smaller model, or increase OLLAMA_TIMEOUT_S in backend/config.py."
        ) from None

    except _ollama.ResponseError as e:  # type: ignore[union-attr]
        msg = str(e).lower()
        status = getattr(e, "status_code", None)
        if status == 404 or "not found" in msg:
            if target_model != OLLAMA_FALLBACK_MODEL:
                print(
                    f"[OLLAMA] model '{target_model}' unavailable, "
                    f"trying fallback '{OLLAMA_FALLBACK_MODEL}'"
                )
                return call_ollama(prompt, model=OLLAMA_FALLBACK_MODEL)
            raise RuntimeError(
                f"Ollama model not available. Run: ollama pull {OLLAMA_MODEL} "
                f"or ollama pull {OLLAMA_FALLBACK_MODEL}"
            ) from e
        raise RuntimeError(f"Ollama API error: {e}") from e

    except Exception as e:
        err = str(e).lower()
        if any(
            k in err
            for k in (
                "connection",
                "refused",
                "connect",
                "unreachable",
                "name or service not known",
                "failed to establish",
            )
        ):
            raise RuntimeError(
                "Ollama server is not reachable. Start it with: ollama serve"
            ) from e
        raise RuntimeError(f"Ollama call failed: {e}") from e


def call_ollama_json(prompt: str, schema_hint: str) -> dict[str, Any]:
    """
    Calls Ollama and parses the response as a JSON object (dict).

    Retries once with stricter instructions if parsing fails.
    On second failure returns _safe_default_decision() (never raises on JSON alone).

    RuntimeError propagates only for connection / timeout from call_ollama.
    """
    json_suffix = (
        f"\n\nRespond ONLY with valid JSON matching this schema:\n{schema_hint}"
        "\nNo explanation. No markdown. No code fences. Just the raw JSON object."
    )

    raw = ""
    try:
        raw = call_ollama(prompt + json_suffix)
        return _parse_json(raw)
    except RuntimeError:
        raise
    except (json.JSONDecodeError, ValueError, TypeError):
        print(f"[OLLAMA] JSON parse failed (attempt 1). Raw head: {raw[:160]!r}")

    try:
        strict_suffix = (
            json_suffix
            + "\n\nCRITICAL: Your entire reply must be one JSON object only. "
            "Start with { and end with }."
        )
        raw = call_ollama(prompt + strict_suffix)
        return _parse_json(raw)
    except RuntimeError:
        raise
    except (json.JSONDecodeError, ValueError, TypeError):
        print(
            f"[OLLAMA] JSON parse failed (attempt 2). Raw head: {raw[:160]!r}. "
            "Using safe default LLMDecision."
        )
        return _safe_default_decision()


def check_ollama_available() -> bool:
    """
    True if the Ollama HTTP API is up and at least one of OLLAMA_MODEL /
    OLLAMA_FALLBACK_MODEL can run a minimal chat. Never raises.
    """
    if not _ollama_ready():
        return False

    def _ping(model_name: str) -> bool:
        def _once() -> None:
            _ollama.chat(
                model=model_name,
                messages=[{"role": "user", "content": "ping"}],
                options={"num_predict": 1},
            )

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                ex.submit(_once).result(timeout=OLLAMA_PING_TIMEOUT_S)
            return True
        except Exception:
            return False

    if _ping(OLLAMA_MODEL):
        return True
    if OLLAMA_FALLBACK_MODEL != OLLAMA_MODEL and _ping(OLLAMA_FALLBACK_MODEL):
        print(
            f"[OLLAMA] Primary '{OLLAMA_MODEL}' not usable; "
            f"fallback '{OLLAMA_FALLBACK_MODEL}' responds."
        )
        return True
    return False


# ── Internal helpers ───────────────────────────────────────────────────────────


def _parse_json(raw: str) -> dict[str, Any]:
    """
    Strip markdown fences, then decode the first JSON object.

    Strategy:
    1. raw_decode — handles trailing text after the closing brace.
    2. If that fails: extract the balanced-brace fragment, sanitize literal
       control characters (\\n, \\r, \\t) inside string values (common llama3
       output defect), then retry json.loads.
    """
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*\n?", "", text, flags=re.MULTILINE)
    text = re.sub(r"\n?```\s*$", "", text, flags=re.MULTILINE)
    text = text.strip()

    start = text.find("{")
    if start == -1:
        raise json.JSONDecodeError("No JSON object found", text, 0)

    candidate = text[start:]

    # Attempt 1: standard raw_decode (handles trailing text after object)
    try:
        decoder = json.JSONDecoder()
        obj, _ = decoder.raw_decode(candidate)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, ValueError):
        pass

    # Attempt 2: extract balanced-brace fragment + sanitize control chars
    end = _find_json_end(candidate)
    if end != -1:
        fragment = _sanitize_json_strings(candidate[: end + 1])
        try:
            obj = json.loads(fragment)
            if isinstance(obj, dict):
                return obj
        except (json.JSONDecodeError, ValueError):
            pass

    raise json.JSONDecodeError("All JSON repair attempts failed", candidate, 0)


def _find_json_end(text: str) -> int:
    """Return the index of the closing } for the outermost JSON object, or -1."""
    depth = 0
    in_string = False
    escaped = False
    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_string:
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _sanitize_json_strings(text: str) -> str:
    """
    Escape raw control characters (\\n \\r \\t) inside JSON string values.
    llama3 sometimes emits literal newlines inside a string field; json.loads
    rejects those but they can be repaired by turning them into \\n sequences.
    """
    result: list[str] = []
    in_string = False
    escaped = False
    for ch in text:
        if escaped:
            result.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_string:
            result.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            result.append(ch)
            continue
        if in_string:
            if ch == "\n":
                result.append("\\n")
                continue
            if ch == "\r":
                result.append("\\r")
                continue
            if ch == "\t":
                result.append("\\t")
                continue
        result.append(ch)
    return "".join(result)


def _safe_default_decision() -> dict[str, Any]:
    """
    Minimal LLMDecision when Ollama output is not parseable (matches state.LLMDecision).
    """
    return {
        "technique": "surface_mapping",
        "target_endpoint": "/",
        "method": "GET",
        "params": {},
        "headers": {},
        "payload": {},
        "rationale": (
            "[FALLBACK — Ollama returned unparseable JSON; defaulting to recon / surface_mapping]"
        ),
        "attack_layer": 1,
    }
