import { useCallback, useEffect, useState } from 'react'
import { fetchState, getWsUrl } from '../api/fetchState'
import type {
  EpisodeReportMessage,
  PatchSummaryMessage,
  StateSnapshot,
  StepUpdateMessage,
} from '../types/arena'

/**
 * Initial load via GET /state; live updates via WebSocket.
 * Handles step_update, episode_report, patch_summary (PROMPT.md §10).
 */
export function useArenaSocket() {
  const [snapshot, setSnapshot] = useState<StateSnapshot | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [wsConnected, setWsConnected] = useState(false)
  const [wsError, setWsError] = useState<string | null>(null)
  const [episodeReport, setEpisodeReport] = useState<EpisodeReportMessage | null>(null)
  const [lastPatchSummary, setLastPatchSummary] = useState<PatchSummaryMessage | null>(null)

  const refetch = useCallback(async () => {
    try {
      const s = await fetchState()
      setSnapshot(s)
      setLoadError(null)
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  useEffect(() => {
    fetchState()
      .then(setSnapshot)
      .catch((e) => setLoadError(e instanceof Error ? e.message : String(e)))
  }, [])

  useEffect(() => {
    const ws = new WebSocket(getWsUrl())

    ws.onopen = () => {
      setWsConnected(true)
      setWsError(null)
    }

    ws.onclose = () => setWsConnected(false)
    ws.onerror = () => setWsError('WebSocket error')

    ws.onmessage = (ev) => {
      try {
        const raw = JSON.parse(ev.data) as Record<string, unknown>
        const t = raw.type as string

        if (t === 'step_update') {
          const m = raw as unknown as StepUpdateMessage
          setSnapshot((prev) => {
            const base = prev ?? ({} as StateSnapshot)
            return {
              ...base,
              episode: m.episode,
              step: m.step,
              risk_score: m.risk_score,
              risk_history: m.risk_history ?? [],
              last_attack: m.last_attack,
              last_defense: m.last_defense,
              active_mitigations: m.active_mitigations ?? base.active_mitigations ?? {},
              vulnerabilities_found: m.vulnerabilities_found ?? [],
              llm_decision: m.llm_decision,
            }
          })
        } else if (t === 'episode_report') {
          setEpisodeReport(raw as unknown as EpisodeReportMessage)
        } else if (t === 'patch_summary') {
          setLastPatchSummary(raw as unknown as PatchSummaryMessage)
          void fetchState()
            .then(setSnapshot)
            .catch(() => {})
        }
      } catch {
        /* ignore */
      }
    }

    return () => ws.close()
  }, [])

  return {
    snapshot,
    loadError,
    wsConnected,
    wsError,
    episodeReport,
    lastPatchSummary,
    refetch,
  }
}
