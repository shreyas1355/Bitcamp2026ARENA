interface Props {
  mitigations: Record<string, boolean>
  blockedIps: string[]
  embedded?: boolean
}

export function MitigationsPanel({ mitigations, blockedIps, embedded }: Props) {
  const active = Object.entries(mitigations).filter(([, v]) => v)

  const inner = (
    <>
      <div className="mb-3">
        <p className="text-xs font-semibold uppercase tracking-wide text-arena-muted">Active flags</p>
        {active.length === 0 ? (
          <p className="text-sm text-arena-muted">None active.</p>
        ) : (
          <ul className="mt-1 flex flex-wrap gap-1">
            {active.map(([k]) => (
              <li
                key={k}
                className="rounded border border-arena-green/30 bg-arena-green-soft px-2 py-0.5 font-mono-telemetry text-xs text-arena-green"
              >
                {k}
              </li>
            ))}
          </ul>
        )}
      </div>
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-arena-muted">Blocked IPs</p>
        {blockedIps.length === 0 ? (
          <p className="text-sm text-arena-muted">None.</p>
        ) : (
          <ul className="mt-1 font-mono-telemetry text-xs text-arena-orange">
            {blockedIps.map((ip) => (
              <li key={ip}>{ip}</li>
            ))}
          </ul>
        )}
      </div>
    </>
  )

  if (embedded) return <div className="text-left">{inner}</div>

  return (
    <section className="rounded-lg border border-arena-border bg-arena-surface p-4 text-left shadow-sm">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-arena-muted">
        Mitigations & blocks
      </h2>
      {inner}
    </section>
  )
}
