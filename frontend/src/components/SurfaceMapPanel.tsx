import { useEffect, useMemo, useState } from 'react'
import type { StepFrame } from '../types/arena'
import { normalizeTargetEndpoint } from '../utils/endpointPath'
import { TARGET_ENDPOINTS } from '../constants/arena'

/** SVG layout: team nodes left, endpoints in an arc. */
const RED: { x: number; y: number } = { x: 56, y: 88 }
const BLUE: { x: number; y: number } = { x: 56, y: 268 }

const ENDPOINT_POS: Record<string, { x: number; y: number }> = {
  '/login': { x: 320, y: 44 },
  '/data': { x: 420, y: 96 },
  '/admin': { x: 500, y: 168 },
  '/transfer': { x: 460, y: 248 },
  '/files': { x: 340, y: 300 },
}

function curvePath(
  x1: number,
  y1: number,
  x2: number,
  y2: number,
  bend: number,
): string {
  const mx = (x1 + x2) / 2
  const my = (y1 + y2) / 2 - bend
  return `M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`
}

interface Props {
  timeline: StepFrame[]
  liveEpisode: number
  viewEpisode: number | 'live'
}

export function SurfaceMapPanel({ timeline, liveEpisode, viewEpisode }: Props) {
  const ep = viewEpisode === 'live' ? liveEpisode : viewEpisode
  const episodeFrames = useMemo(
    () =>
      timeline
        .filter((f) => f.episode === ep)
        .sort((a, b) => a.step - b.step),
    [timeline, ep],
  )

  const maxStep = useMemo(
    () => (episodeFrames.length ? Math.max(...episodeFrames.map((f) => f.step)) : 0),
    [episodeFrames],
  )

  const [playhead, setPlayhead] = useState(maxStep)
  useEffect(() => {
    setPlayhead(maxStep)
  }, [maxStep, ep])

  const visible = episodeFrames.filter((f) => f.step <= playhead)

  type Edge = {
    key: string
    kind: 'attack' | 'defense'
    d: string
    stroke: string
    step: number
  }

  const edges = useMemo(() => {
    const out: Edge[] = []
    for (const f of visible) {
      const atk = f.last_attack
      if (!atk) continue
      const tgt = normalizeTargetEndpoint(
        atk.target ?? f.llm_decision?.target_endpoint ?? '',
      )
      if (tgt && ENDPOINT_POS[tgt]) {
        const p = ENDPOINT_POS[tgt]!
        const bend = 24 + (f.step % 5) * 6
        const ok = atk.result === 'success'
        out.push({
          key: `a-${f.episode}-${f.step}`,
          kind: 'attack',
          d: curvePath(RED.x, RED.y, p.x, p.y, bend),
          stroke: ok ? '#15803d' : '#b91c1c',
          step: f.step,
        })
      }
      const d = f.last_defense
      if (d && d.action && d.action !== 'none') {
        const tgt = normalizeTargetEndpoint(d.target_endpoint)
        if (tgt && ENDPOINT_POS[tgt]) {
          const p = ENDPOINT_POS[tgt]!
          const bend = 18 + (f.step % 4) * 5
          out.push({
            key: `d-${f.episode}-${f.step}`,
            kind: 'defense',
            d: curvePath(BLUE.x, BLUE.y, p.x, p.y, -bend),
            stroke: '#1d4ed8',
            step: f.step,
          })
        }
      }
    }
    return out
  }, [visible])

  const sortedVisible = useMemo(
    () => [...visible].sort((a, b) => a.step - b.step),
    [visible],
  )

  const frameAtPlayhead = useMemo(() => {
    const le = sortedVisible.filter((f) => f.step <= playhead)
    return le.length ? le[le.length - 1]! : null
  }, [sortedVisible, playhead])

  const metrics = useMemo(() => {
    let ok = 0
    let bad = 0
    let blk = 0
    for (const f of visible) {
      const r = f.last_attack?.result
      if (r === 'success') ok++
      else if (r === 'blocked' || r === 'rate_limited') blk++
      else if (f.last_attack) bad++
    }
    const touched = new Set<string>()
    for (const f of visible) {
      const t = normalizeTargetEndpoint(
        f.last_attack?.target ?? f.llm_decision?.target_endpoint ?? '',
      )
      if (t) touched.add(t)
    }
    return { ok, bad, blk, attempts: visible.filter((f) => f.last_attack).length, touched: touched.size }
  }, [visible])

  const riskAtPlayhead =
    frameAtPlayhead != null ? `${(Math.min(1, Math.max(0, frameAtPlayhead.risk_score)) * 100).toFixed(1)}%` : '—'

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
      <section className="rounded-lg border border-arena-border bg-arena-surface p-4 shadow-sm">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className="font-serif text-lg font-semibold text-arena-text">Surface map</h2>
          <span className="text-xs text-arena-muted">Episode {ep}</span>
        </div>
        <div className="mb-3 flex flex-wrap items-center gap-3 text-xs text-arena-muted">
          <label className="flex items-center gap-2">
            <span>Replay step</span>
            <input
              type="range"
              min={0}
              max={Math.max(0, maxStep)}
              value={Math.min(playhead, maxStep)}
              onChange={(e) => setPlayhead(Number(e.target.value))}
              className="w-40 accent-arena-accent"
            />
            <span className="font-mono-telemetry tabular-nums text-arena-text">
              {playhead} / {maxStep}
            </span>
          </label>
        </div>
        <svg
          viewBox="0 0 560 340"
          className="h-auto w-full rounded border border-arena-border bg-arena-bg"
          role="img"
          aria-label="Attack and defense flows to endpoints"
        >
          <text x="8" y="20" className="fill-arena-muted text-[10px]">
            Legend: attack success (green) · fail (red) · defense (blue)
          </text>
          {edges.map((e) => (
            <path
              key={e.key}
              d={e.d}
              fill="none"
              stroke={e.stroke}
              strokeWidth="2"
              strokeOpacity={0.88}
              strokeLinecap="round"
              className="transition-opacity duration-300 ease-out"
            />
          ))}
          <g>
            <rect
              x={RED.x - 6}
              y={RED.y - 14}
              width="88"
              height="28"
              rx="4"
              className="fill-arena-red-soft stroke-arena-red"
              strokeWidth="1"
            />
            <text x={RED.x + 38} y={RED.y + 4} textAnchor="middle" className="fill-arena-red text-[11px] font-semibold">
              Red team
            </text>
          </g>
          <g>
            <rect
              x={BLUE.x - 6}
              y={BLUE.y - 14}
              width="92"
              height="28"
              rx="4"
              className="fill-arena-blue-soft stroke-arena-blue"
              strokeWidth="1"
            />
            <text
              x={BLUE.x + 40}
              y={BLUE.y + 4}
              textAnchor="middle"
              className="fill-arena-blue text-[11px] font-semibold"
            >
              Blue team
            </text>
          </g>
          {TARGET_ENDPOINTS.map((path) => {
            const p = ENDPOINT_POS[path]
            if (!p) return null
            return (
              <g key={path}>
                <circle cx={p.x} cy={p.y} r="22" className="fill-arena-surface stroke-arena-border" strokeWidth="1.5" />
                <text
                  x={p.x}
                  y={p.y + 4}
                  textAnchor="middle"
                  className="fill-arena-text font-mono-telemetry text-[10px]"
                >
                  {path}
                </text>
              </g>
            )
          })}
        </svg>
      </section>
      <aside className="space-y-4">
        <div className="rounded-lg border border-arena-border bg-arena-surface p-4 shadow-sm">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-arena-muted">
            Metrics (through step {playhead})
          </h3>
          <dl className="grid grid-cols-2 gap-x-3 gap-y-2 text-sm">
            <dt className="text-arena-muted">Risk (end of step {playhead})</dt>
            <dd className="font-mono-telemetry text-right text-arena-text">{riskAtPlayhead}</dd>
            <dt className="text-arena-muted">Attempts</dt>
            <dd className="font-mono-telemetry text-right">{metrics.attempts}</dd>
            <dt className="text-arena-muted">Success</dt>
            <dd className="text-right font-medium text-arena-green">{metrics.ok}</dd>
            <dt className="text-arena-muted">Failed</dt>
            <dd className="text-right font-medium text-arena-red">{metrics.bad}</dd>
            <dt className="text-arena-muted">Blocked / limited</dt>
            <dd className="text-right font-medium text-arena-orange">{metrics.blk}</dd>
            <dt className="text-arena-muted">Endpoints touched</dt>
            <dd className="font-mono-telemetry text-right">{metrics.touched}</dd>
          </dl>
        </div>
        <div className="max-h-80 overflow-auto rounded-lg border border-arena-border bg-arena-surface shadow-sm">
          <table className="w-full border-collapse text-left text-xs">
            <thead className="sticky top-0 bg-arena-table-header text-arena-muted">
              <tr>
                <th className="border-b border-arena-border px-2 py-1.5 font-medium">Step</th>
                <th className="border-b border-arena-border px-2 py-1.5 font-medium">Risk</th>
                <th className="border-b border-arena-border px-2 py-1.5 font-medium">Attack</th>
                <th className="border-b border-arena-border px-2 py-1.5 font-medium">Result</th>
                <th className="border-b border-arena-border px-2 py-1.5 font-medium">Rationale</th>
              </tr>
            </thead>
            <tbody>
              {sortedVisible.slice(-40).map((f) => {
                const rat = f.llm_decision?.rationale?.trim()
                return (
                  <tr key={`${f.episode}-${f.step}`} className="border-b border-arena-border/80 align-top">
                    <td className="px-2 py-1 font-mono-telemetry text-arena-text">{f.step}</td>
                    <td className="whitespace-nowrap px-2 py-1 font-mono-telemetry text-arena-text">
                      {(Math.min(1, Math.max(0, f.risk_score)) * 100).toFixed(1)}%
                    </td>
                    <td className="px-2 py-1 font-mono-telemetry text-arena-text">
                      {f.last_attack?.type ?? '—'}
                    </td>
                    <td
                      className={`px-2 py-1 font-medium ${
                        !f.last_attack
                          ? 'text-arena-muted'
                          : f.last_attack?.result === 'success'
                            ? 'text-arena-green'
                            : f.last_attack?.result === 'blocked' || f.last_attack?.result === 'rate_limited'
                              ? 'text-arena-orange'
                              : 'text-arena-red'
                      }`}
                    >
                      {f.last_attack?.result ?? '—'}
                    </td>
                    <td className="max-w-[16rem] px-2 py-1 text-arena-muted" title={rat || undefined}>
                      {rat ? <span className="block max-h-[3.5rem] overflow-hidden text-[11px] leading-snug">{rat}</span> : '—'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </aside>
    </div>
  )
}
