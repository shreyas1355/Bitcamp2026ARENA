interface Props {
  layer: number
}

const LAYERS = [
  { n: 1, label: 'Network' },
  { n: 2, label: 'Auth' },
  { n: 3, label: 'Authz' },
  { n: 4, label: 'Input' },
  { n: 5, label: 'Logic' },
  { n: 6, label: 'Evasion' },
]

export function AttackLayerStrip({ layer }: Props) {
  return (
    <div className="flex flex-wrap items-center gap-1 text-[11px] text-arena-muted">
      <span className="mr-1 font-semibold uppercase tracking-wide">Attack layer</span>
      {LAYERS.map(({ n, label }) => (
        <span
          key={n}
          className={`rounded border px-1.5 py-0.5 font-mono-telemetry ${
            n === layer
              ? 'border-arena-accent bg-arena-blue-soft font-semibold text-arena-accent'
              : 'border-arena-border bg-arena-surface text-arena-muted'
          }`}
          title={`Layer ${n}`}
        >
          {n}:{label}
        </span>
      ))}
    </div>
  )
}
