interface Props {
  riskScore: number
  riskHistory: number[]
}

export function RiskGauge({ riskScore, riskHistory }: Props) {
  const pct = Math.min(100, Math.round(riskScore * 100))
  const recent = riskHistory.slice(-24)

  return (
    <section className="rounded-lg border border-arena-border bg-arena-surface p-4 text-left">
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-arena-muted">
        Risk score
      </h2>
      <div className="mb-2 flex items-end gap-2">
        <span className="text-4xl font-semibold tabular-nums text-arena-text">
          {riskScore.toFixed(3)}
        </span>
        <span className="text-sm text-arena-muted">({pct}% scale)</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-arena-border">
        <div
          className="h-full rounded-full bg-gradient-to-r from-arena-green via-arena-yellow to-arena-red transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      {recent.length > 0 && (
        <div className="mt-4 flex h-12 items-end gap-px">
          {recent.map((v, i) => (
            <div
              key={i}
              className="min-w-[3px] flex-1 rounded-sm bg-arena-blue/70"
              style={{ height: `${Math.min(100, v * 100)}%` }}
              title={v.toFixed(3)}
            />
          ))}
        </div>
      )}
    </section>
  )
}
