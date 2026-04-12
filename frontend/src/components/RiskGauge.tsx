import type { StepFrame } from '../types/arena'

interface Props {
  episode: number
  riskScore: number
  riskHistory: number[]
  /** Same-episode frames (sorted by step) for annotating sharp moves. */
  stepFrames: StepFrame[]
}

const VB_W = 720
const VB_H = 340
const ML = 56
const MR = 28
const MT = 44
const MB = 56
const PW = VB_W - ML - MR
const PH = VB_H - MT - MB

const Y_TICKS = [0, 0.5, 1] as const
const DELTA_THRESH = 0.045

function clampUnit(v: unknown): number {
  const n = typeof v === 'number' ? v : Number(v)
  if (!Number.isFinite(n)) return 0
  return Math.min(1, Math.max(0, n))
}

function ySvg(v: number): number {
  return MT + (1 - v) * PH
}

function xSvg(i: number, n: number): number {
  if (n <= 1) return ML + PW / 2
  return ML + (i / (n - 1)) * PW
}

function frameForStep(frames: StepFrame[], step: number): StepFrame | undefined {
  return frames.find((f) => f.step === step)
}

function classifyMove(
  delta: number,
  frame: StepFrame | undefined,
): { fill: string; label: string } | null {
  if (!frame || Math.abs(delta) < DELTA_THRESH) return null
  if (delta < 0) {
    const a = frame.last_defense?.action
    if (a && a !== 'none' && a !== 'alert_only') {
      return { fill: '#2563eb', label: 'Defense fired' }
    }
    return { fill: '#64748b', label: 'Risk eased' }
  }
  if (frame.last_attack?.result === 'success') {
    return { fill: '#dc2626', label: 'Attack landed' }
  }
  if (frame.last_attack) {
    return { fill: '#b45309', label: 'Risk rose' }
  }
  return { fill: '#64748b', label: 'Risk rose' }
}

/**
 * Risk headline (percent only) + timeline chart with labeled axes and event markers.
 */
export function RiskGauge({ episode, riskScore, riskHistory, stepFrames }: Props) {
  const rawSeries = riskHistory.length > 0 ? riskHistory : [riskScore]
  const series = rawSeries.map(clampUnit)
  const n = series.length
  const pctStr = `${(clampUnit(riskScore) * 100).toFixed(1)}%`

  const pointsAttr = series.map((v, i) => `${xSvg(i, n)},${ySvg(v)}`).join(' ')

  const markers: { i: number; cx: number; cy: number; fill: string; label: string }[] = []
  for (let i = 1; i < n; i++) {
    const delta = series[i]! - series[i - 1]!
    const step = i + 1
    const fr = frameForStep(stepFrames, step)
    const m = classifyMove(delta, fr)
    if (m) {
      markers.push({
        i,
        cx: xSvg(i, n),
        cy: ySvg(series[i]!),
        fill: m.fill,
        label: m.label,
      })
    }
  }

  const xTickCount = Math.min(6, Math.max(2, n))
  const xTicks: { x: number; label: string }[] = []
  if (n <= 1) {
    xTicks.push({ x: xSvg(0, n), label: '1' })
  } else {
    for (let t = 0; t < xTickCount; t++) {
      const idx = Math.round((t / (xTickCount - 1)) * (n - 1))
      xTicks.push({ x: xSvg(idx, n), label: String(idx + 1) })
    }
  }

  return (
    <section className="rounded-lg border border-arena-border bg-arena-surface p-5 text-left shadow-sm">
      <h2 className="mb-1 text-xs font-semibold uppercase tracking-wider text-arena-muted">
        Risk timeline — episode {episode}
      </h2>
      <div className="mb-4">
        <span className="text-5xl font-semibold tabular-nums tracking-tight text-arena-text">{pctStr}</span>
      </div>
      <div className="w-full overflow-x-auto">
        <svg
          viewBox={`0 0 ${VB_W} ${VB_H}`}
          className="h-[min(22rem,55vw)] w-full min-w-[320px] max-w-full text-arena-accent"
          preserveAspectRatio="xMidYMid meet"
          role="img"
          aria-label={`Risk score over steps, episode ${episode}`}
        >
          <title>Risk history</title>

          {Y_TICKS.map((tv) => {
            const yy = ySvg(tv)
            return (
              <g key={`gy-${tv}`}>
                <line
                  x1={ML}
                  y1={yy}
                  x2={VB_W - MR}
                  y2={yy}
                  className="stroke-arena-border"
                  strokeWidth="1"
                  strokeOpacity={0.85}
                />
                <text x={ML - 8} y={yy + 4} textAnchor="end" className="fill-arena-muted text-[11px] font-mono-telemetry">
                  {tv.toFixed(1)}
                </text>
              </g>
            )
          })}

          <line
            x1={ML}
            y1={MT}
            x2={ML}
            y2={VB_H - MB}
            className="stroke-arena-border"
            strokeWidth="1.25"
          />
          <line
            x1={ML}
            y1={VB_H - MB}
            x2={VB_W - MR}
            y2={VB_H - MB}
            className="stroke-arena-border"
            strokeWidth="1.25"
          />

          <text
            x={12}
            y={MT + PH / 2}
            transform={`rotate(-90 12 ${MT + PH / 2})`}
            textAnchor="middle"
            className="fill-arena-muted text-[12px] font-medium"
          >
            Risk score
          </text>
          <text
            x={ML + PW / 2}
            y={VB_H - 12}
            textAnchor="middle"
            className="fill-arena-muted text-[12px] font-medium"
          >
            Step (episode)
          </text>

          {xTicks.map((t, idx) => (
            <g key={`xt-${idx}`}>
              <line
                x1={t.x}
                y1={VB_H - MB}
                x2={t.x}
                y2={VB_H - MB + 6}
                className="stroke-arena-border"
                strokeWidth="1"
              />
              <text x={t.x} y={VB_H - MB + 22} textAnchor="middle" className="fill-arena-muted text-[11px] font-mono-telemetry">
                {t.label}
              </text>
            </g>
          ))}

          {pointsAttr ? (
            <polyline
              fill="none"
              stroke="#ea580c"
              strokeWidth="2.25"
              strokeLinejoin="round"
              strokeLinecap="round"
              points={pointsAttr}
            />
          ) : null}

          {markers.map((m) => (
            <circle key={`mk-${m.i}`} cx={m.cx} cy={m.cy} r={5} fill={m.fill} stroke="#0f172a" strokeOpacity={0.15} strokeWidth={1}>
              <title>{m.label}</title>
            </circle>
          ))}

          {n > 0 && !markers.some((m) => m.i === n - 1) ? (
            <circle
              cx={xSvg(n - 1, n)}
              cy={ySvg(series[n - 1]!)}
              r={5}
              fill="#64748b"
              stroke="#0f172a"
              strokeOpacity={0.12}
              strokeWidth={1}
            >
              <title>Latest</title>
            </circle>
          ) : null}
        </svg>
      </div>

      <div className="mt-3 flex flex-wrap gap-4 text-xs text-arena-muted">
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full bg-[#dc2626]" />
          Attack landed
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full bg-[#2563eb]" />
          Defense fired
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full bg-[#64748b]" />
          Other / latest
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-3 w-6 rounded-sm bg-[#ea580c]" />
          Risk path
        </span>
      </div>
    </section>
  )
}
