import { useCallback, useEffect, useMemo, useState } from 'react'
import { fetchState, getWsUrl } from '../api/fetchState'
import type {
  EpisodeReportMessage,
  PatchSummaryMessage,
  StateSnapshot,
  StepFrame,
  StepUpdateMessage,
} from '../types/arena'

const MAX_TIMELINE_FRAMES = 4000

/**
 * Initial load via GET /state; live updates via WebSocket.
 * Buffers step frames per episode for replay, surface map, and episode drill-down.
 */
export function useArenaSocket() {
  const [snapshot, setSnapshot] = useState<StateSnapshot | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [wsConnected, setWsConnected] = useState(false)
  const [wsError, setWsError] = useState<string | null>(null)
  const [episodeReport, setEpisodeReport] = useState<EpisodeReportMessage | null>(null)
  const [lastPatchSummary, setLastPatchSummary] = useState<PatchSummaryMessage | null>(null)
  const [timeline, setTimeline] = useState<StepFrame[]>([])
  const [reportsByEpisode, setReportsByEpisode] = useState<
    Record<number, Record<string, unknown>>
  >({})
  const [viewEpisode, setViewEpisode] = useState<number | 'live'>('live')

  const appendFrame = useCallback((m: StepUpdateMessage) => {
    const frame: StepFrame = {
      episode: m.episode,
      step: m.step,
      risk_score: m.risk_score,
      risk_history: m.risk_history ?? [],
      last_attack: m.last_attack,
      last_defense: m.last_defense,
      active_mitigations: m.active_mitigations ?? {},
      vulnerabilities_found: m.vulnerabilities_found ?? [],
      llm_decision: m.llm_decision,
      current_attack_layer: m.current_attack_layer ?? 1,
      last_prune_removed: m.last_prune_removed,
    }
    setTimeline((prev) => {
      const next = prev.filter(
        (f) => !(f.episode === frame.episode && f.step === frame.step),
      )
      next.push(frame)
      if (next.length > MAX_TIMELINE_FRAMES) {
        return next.slice(-MAX_TIMELINE_FRAMES)
      }
      return next
    })
  }, [])

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
      .then((s) => {
        setSnapshot(s)
        setTimeline((prev) => {
          if (prev.length > 0) return prev
          const frame: StepFrame = {
            episode: s.episode,
            step: s.step,
            risk_score: s.risk_score,
            risk_history: s.risk_history ?? [],
            last_attack: s.last_attack,
            last_defense: s.last_defense,
            active_mitigations: s.active_mitigations ?? {},
            vulnerabilities_found: s.vulnerabilities_found ?? [],
            llm_decision: s.llm_decision,
            current_attack_layer: s.current_attack_layer ?? 1,
            last_prune_removed: s.last_prune_removed,
          }
          return [frame]
        })
      })
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
          appendFrame(m)
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
              current_attack_layer: m.current_attack_layer ?? base.current_attack_layer ?? 1,
              patch_records: m.patch_records ?? base.patch_records ?? [],
              last_prune_removed: m.last_prune_removed ?? base.last_prune_removed ?? [],
            }
          })
        } else if (t === 'episode_report') {
          const er = raw as unknown as EpisodeReportMessage
          setEpisodeReport(er)
          setReportsByEpisode((prev) => ({
            ...prev,
            [er.episode]: er.report,
          }))
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
  }, [appendFrame])

  const episodeNumbers = useMemo(() => {
    const set = new Set<number>()
    for (const f of timeline) set.add(f.episode)
    return Array.from(set).sort((a, b) => b - a)
  }, [timeline])

  /** Latest buffered frame for a finished episode (or current) when drilling down. */
  const replayFrame = useMemo(() => {
    if (!snapshot) return null
    if (viewEpisode === 'live') return null
    const frames = timeline.filter((f) => f.episode === viewEpisode)
    if (frames.length === 0) return null
    return frames.reduce((a, b) => (a.step >= b.step ? a : b))
  }, [snapshot, timeline, viewEpisode])

  const displaySnapshot = useMemo((): StateSnapshot | null => {
    if (!snapshot) return null
    if (viewEpisode === 'live' || replayFrame == null) return snapshot
    return {
      ...snapshot,
      episode: replayFrame.episode,
      step: replayFrame.step,
      risk_score: replayFrame.risk_score,
      risk_history: replayFrame.risk_history,
      last_attack: replayFrame.last_attack,
      last_defense: replayFrame.last_defense,
      active_mitigations: replayFrame.active_mitigations,
      vulnerabilities_found: replayFrame.vulnerabilities_found,
      llm_decision: replayFrame.llm_decision,
      current_attack_layer: replayFrame.current_attack_layer,
      last_prune_removed: replayFrame.last_prune_removed ?? snapshot.last_prune_removed ?? [],
    }
  }, [replayFrame, snapshot, viewEpisode])

  return {
    snapshot,
    displaySnapshot,
    loadError,
    wsConnected,
    wsError,
    episodeReport,
    lastPatchSummary,
    refetch,
    timeline,
    episodeNumbers,
    reportsByEpisode,
    viewEpisode,
    setViewEpisode,
  }
}
