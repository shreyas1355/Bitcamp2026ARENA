interface Props {
  mitigations: Record<string, boolean>
  blockedIps: string[]
}

export function MitigationsPanel({ mitigations, blockedIps }: Props) {
  const active = Object.entries(mitigations).filter(([, v]) => v)

  return (
    <section className="rounded-lg border border-arena-border bg-arena-surface p-4 text-left">
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-arena-muted">
        Mitigations & blocks
      </h2>
      <div className="mb-3">
        <p className="text-xs font-medium uppercase text-arena-muted">Active flags</p>
        {active.length === 0 ? (
          <p className="text-sm text-arena-muted">None active.</p>
        ) : (
          <ul className="mt-1 flex flex-wrap gap-1">
            {active.map(([k]) => (
              <li
                key={k}
                className="rounded bg-arena-green/15 px-2 py-0.5 font-mono text-xs text-arena-green"
              >
                {k}
              </li>
            ))}
          </ul>
        )}
      </div>
      <div>
        <p className="text-xs font-medium uppercase text-arena-muted">Blocked IPs</p>
        {blockedIps.length === 0 ? (
          <p className="text-sm text-arena-muted">None.</p>
        ) : (
          <ul className="mt-1 font-mono text-xs text-arena-orange">
            {blockedIps.map((ip) => (
              <li key={ip}>{ip}</li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}
