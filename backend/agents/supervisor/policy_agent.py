"""
policy_node — post-episode Gemini analysis (ONLY node that calls Gemini).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

from backend.memory.episode_pool import append_summary, get_recent
from backend.state import SystemState
from backend.ws.broadcaster import broadcast_episode_report

POLICY_SYSTEM_PROMPT = """You are a senior cybersecurity analyst AI reviewing one episode of automated adversarial testing against a web application.

Your analysis must be grounded in the provided data only. Do not fabricate vulnerabilities not evidenced in the data.

You will receive:
- PRUNED OBSERVATION: Key security metrics from the final state of the episode (pre-filtered by structural entropy to show only high-signal attributes)
- ATTACK HISTORY: The last 10 attack events from this episode
- DEFENSE ACTIONS: Mitigations applied during this episode
- VULNERABILITIES FOUND: Confirmed findings from the rule-based detection system
- EPISODE SUMMARIES: Lessons from previous episodes (may be empty for episode 1)
- KNOWLEDGE BASE: Relevant CVE patterns and security rules

Your output must be valid JSON and nothing else. No markdown, no explanations outside the JSON structure."""

POLICY_USER_PROMPT = """EPISODE {episode} SUMMARY

PRUNED OBSERVATION (high-entropy attributes only):
{pruned_obs_json}

ATTACK HISTORY (last 10 events):
{attack_history_json}

DEFENSE ACTIONS TAKEN:
{defense_history_json}

RULE-BASED FINDINGS:
{vulnerabilities_json}

PREVIOUS EPISODE SUMMARIES:
{episode_pool_excerpts}

KNOWLEDGE BASE EXCERPTS:
{knowledge_snippets}

Produce your analysis as this exact JSON schema:
{{
  "risk_score": <float 0.0-1.0>,
  "vulnerabilities": [
    {{
      "name": "<vulnerability name>",
      "severity": "<low|medium|high|critical>",
      "endpoint": "<affected endpoint path>",
      "cwe": "<CWE-XXX>",
      "evidence": "<one sentence of evidence from the data>",
      "first_exploited_step": <int>,
      "exploit_payload": "<the specific payload string that confirmed this vulnerability>"
    }}
  ],
  "mitigations": ["<concrete mitigation step>"],
  "next_episode_strategy": "<one sentence strategy recommendation for the red team>",
  "episode_summary": "<two sentence summary for the memory pool>"
}}"""


def _kb_excerpts(state: SystemState, max_items: int = 3) -> List[str]:
    kb = state.get("knowledge_base") or []
    hints: List[str] = []
    for v in state.get("vulnerabilities_found") or []:
        hints.extend(re.findall(r"[a-zA-Z]{3,}", str(v).lower()))
    seen: set[str] = set()
    out: List[str] = []
    for entry in kb:
        if len(out) >= max_items:
            break
        if not isinstance(entry, dict):
            continue
        tags = " ".join(entry.get("tags") or []).lower()
        content = str(entry.get("content", ""))
        eid = str(entry.get("id", ""))
        blob = f"{tags} {content}".lower()
        match = not hints or any(h in blob for h in hints if len(h) > 3)
        if not match and hints:
            continue
        key = eid or content[:80]
        if key in seen:
            continue
        seen.add(key)
        out.append(f"[{eid}] {content[:500]}")
    for entry in kb:
        if len(out) >= max_items:
            break
        if not isinstance(entry, dict):
            continue
        content = str(entry.get("content", ""))
        kid = str(entry.get("id", ""))
        if content and kid not in seen:
            seen.add(kid)
            out.append(f"[{kid}] {content[:500]}")
    return out[:max_items]


def _last_n_memories(state: SystemState, n: int) -> List[Dict[str, Any]]:
    mem = state.get("short_term_memory") or []
    return mem[-n:] if len(mem) > n else list(mem)


def _parse_policy_json(raw: str) -> Dict[str, Any]:
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence:
        text = fence.group(1).strip()
    return json.loads(text)


def _report_from_parsed(data: Dict[str, Any], state: SystemState, raw_len: int) -> Dict[str, Any]:
    return {
        "risk_score": float(data.get("risk_score", state.get("risk_score", 0.0))),
        "vulnerabilities": list(data.get("vulnerabilities") or []),
        "mitigations": list(data.get("mitigations") or []),
        "next_episode_strategy": str(data.get("next_episode_strategy", "")),
        "episode_summary": str(data.get("episode_summary", "")),
        "token_count": max(1, raw_len // 4),
    }


def _fallback_report(state: SystemState, reason: str) -> Dict[str, Any]:
    return {
        "risk_score": float(state.get("risk_score", 0.0)),
        "vulnerabilities": [
            {
                "name": str(v)[:120],
                "severity": "medium",
                "endpoint": "unknown",
                "cwe": "",
                "evidence": "rule-based detection",
            }
            for v in (state.get("vulnerabilities_found") or [])[:5]
        ],
        "mitigations": [
            f"Supervisor fallback ({reason}) — set GEMINI_API_KEY for full Gemini analysis."
        ],
        "next_episode_strategy": "Continue automated testing; expand coverage on high-risk endpoints.",
        "episode_summary": (
            f"Episode {state.get('episode', 0)}: {reason}. "
            f"Final risk score {state.get('risk_score', 0.0):.2f}."
        ),
        "token_count": 0,
    }


def policy_node(state: SystemState) -> Dict[str, Any]:
    ep = int(state.get("episode", 1))
    print(f"\n[SUPERVISOR] Episode {ep} analysis starting...")

    pruned = state.get("pruned_observation") or {}
    mem_slice = _last_n_memories(state, 10)
    attacks = [e.get("attack") for e in mem_slice if e.get("attack")]
    defenses = [e.get("defense") for e in mem_slice if e.get("defense")]

    user = POLICY_USER_PROMPT.format(
        episode=ep,
        pruned_obs_json=json.dumps(pruned, indent=2)[:8000],
        attack_history_json=json.dumps(attacks, indent=2)[:12000],
        defense_history_json=json.dumps(defenses, indent=2)[:8000],
        vulnerabilities_json=json.dumps(state.get("vulnerabilities_found") or [], indent=2),
        episode_pool_excerpts=json.dumps(get_recent(3), indent=2),
        knowledge_snippets=json.dumps(_kb_excerpts(state), indent=2),
    )

    from backend.agents.supervisor.gemini_client import call_gemini, is_configured

    if not os.environ.get("GEMINI_API_KEY") or not is_configured():
        report = _fallback_report(state, "GEMINI_API_KEY not set")
    else:
        try:
            raw = call_gemini(POLICY_SYSTEM_PROMPT, user)
            data = _parse_policy_json(raw)
            report = _report_from_parsed(data, state, len(raw))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            print(f"[SUPERVISOR] JSON parse failed ({e}), one retry with stricter instruction...")
            try:
                raw2 = call_gemini(
                    POLICY_SYSTEM_PROMPT,
                    user + "\n\nRespond with raw JSON only. No markdown code fences.",
                )
                data = _parse_policy_json(raw2)
                report = _report_from_parsed(data, state, len(raw2))
            except Exception as e2:
                print(f"[SUPERVISOR] Retry failed: {e2}")
                report = _fallback_report(state, "JSON parse failure")
        except Exception as e:
            print(f"[SUPERVISOR] Gemini error: {e}")
            report = _fallback_report(state, str(e)[:200])

    summary = report.get("episode_summary") or f"Episode {ep} summary."
    updated_pool = append_summary(str(summary))
    broadcast_episode_report(report, ep)

    # V2: Ingest IOC exports into the knowledge base.
    # Blue team anomaly rules append new attack patterns to ioc_exports during
    # the episode. We add them to knowledge_base here so the next episode's
    # Gemini prompt includes these newly discovered patterns.
    updated_kb = list(state.get("knowledge_base") or [])
    ioc_exports = state.get("ioc_exports") or []
    new_ioc_count = 0
    for ioc in ioc_exports:
        kb_entry = ioc.get("kb_entry")
        if kb_entry and isinstance(kb_entry, dict):
            # Deduplicate by id field if present
            existing_ids = {e.get("id") for e in updated_kb if isinstance(e, dict)}
            entry_id = kb_entry.get("id")
            if entry_id and entry_id in existing_ids:
                continue
            updated_kb.append(kb_entry)
            new_ioc_count += 1

    if new_ioc_count:
        print(f"[SUPERVISOR] Ingested {new_ioc_count} new IOC(s) into knowledge base.")
        # Persist the runtime additions to a separate file (never overwrite base KB)
        _persist_runtime_kb(updated_kb)

    print(f"[SUPERVISOR] Episode {ep} complete. Risk: {report['risk_score']:.3f}")
    return {
        "supervisor_report": report,
        "episode_pool":      updated_pool,
        "knowledge_base":    updated_kb,
    }


def _persist_runtime_kb(kb: list) -> None:
    """
    Persists the runtime-extended knowledge base to a separate file.
    Never overwrites data/knowledge_base.json (the base file is read-only).
    """
    import json
    runtime_path = "data/knowledge_base_runtime.json"
    try:
        with open(runtime_path, "w") as f:
            json.dump(kb, f, indent=2)
    except OSError as e:
        print(f"[SUPERVISOR] Could not persist runtime KB: {e}")
