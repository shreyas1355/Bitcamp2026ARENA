import type { StepFrame } from '../types/arena'

interface Props {
  episodeNumbers: number[]
  timeline: StepFrame[]
  viewEpisode: number | 'live'
  liveEpisode: number
  liveStep: number
  onSelect: (ep: number | 'live') => void
}

export function EpisodesPanel({
  episodeNumbers,
  timeline,
  viewEpisode,
  liveEpisode,
  liveStep,
  onSelect,
}: Props) {
  const rows = episodeNumbers.map((ep) => {
    const frames = timeline.filter((f) => f.episode === ep)
    const maxStep = frames.length ? Math.max(...frames.map((f) => f.step)) : 0
    const lastRisk = frames.length
      ? frames.reduce((a, b) => (a.step > b.step ? a : b)).risk_score
      : null
    return { ep, steps: frames.length, maxStep, lastRisk }
  })

  return (
    <div className="space-y-4">
      <p className="text-sm text-arena-muted">
        Buffered steps in this browser session. Select an episode to freeze overview panels to its
        final captured step, or use <strong>Surface map</strong> to scrub within an episode.
      </p>
      <div className="overflow-x-auto rounded-lg border border-arena-border bg-arena-surface shadow-sm">
        <table className="w-full border-collapse text-left text-sm">
          <thead>
            <tr className="border-b border-arena-border bg-arena-table-header text-xs font-semibold uppercase tracking-wide text-arena-muted">
              <th className="px-3 py-2">Episode</th>
              <th className="px-3 py-2">Frames</th>
              <th className="px-3 py-2">Max step</th>
              <th className="px-3 py-2">Last risk</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-arena-border bg-arena-green-soft/40">
              <td className="px-3 py-2 font-medium text-arena-text">Live</td>
              <td className="px-3 py-2 font-mono-telemetry text-arena-text">
                {timeline.filter((f) => f.episode === liveEpisode).length}
              </td>
              <td className="px-3 py-2 font-mono-telemetry text-arena-text">{liveStep}</td>
              <td className="px-3 py-2 font-mono-telemetry text-arena-muted">—</td>
              <td className="px-3 py-2 text-right">
                <button
                  type="button"
                  onClick={() => onSelect('live')}
                  className={`rounded border px-2 py-1 text-xs font-medium ${
                    viewEpisode === 'live'
                      ? 'border-arena-accent bg-arena-blue-soft text-arena-accent'
                      : 'border-arena-border text-arena-muted hover:bg-arena-muted-bg'
                  }`}
                >
                  Follow live
                </button>
              </td>
            </tr>
            {rows.map(({ ep, steps, maxStep, lastRisk }) => (
              <tr key={ep} className="border-b border-arena-border/90">
                <td className="px-3 py-2 font-mono-telemetry font-medium text-arena-text">{ep}</td>
                <td className="px-3 py-2 font-mono-telemetry text-arena-muted">{steps}</td>
                <td className="px-3 py-2 font-mono-telemetry text-arena-text">{maxStep}</td>
                <td className="px-3 py-2 font-mono-telemetry text-arena-text">
                  {lastRisk != null ? lastRisk.toFixed(3) : '—'}
                </td>
                <td className="px-3 py-2 text-right">
                  <button
                    type="button"
                    onClick={() => onSelect(ep)}
                    className={`rounded border px-2 py-1 text-xs font-medium ${
                      viewEpisode === ep
                        ? 'border-arena-accent bg-arena-blue-soft text-arena-accent'
                        : 'border-arena-border text-arena-muted hover:bg-arena-muted-bg'
                    }`}
                  >
                    View
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
