import type { DefenseEvent } from '../types/arena'

interface Props {
  defense: DefenseEvent | null
  embedded?: boolean
}

export function DefensePanel({ defense, embedded }: Props) {
  const active = defense && defense.action !== 'none'

  const inner = !defense ? (
    <p className="text-sm text-arena-muted">No defense event yet.</p>
  ) : (
    <dl className="grid gap-2 text-sm">
      <div className="flex justify-between gap-2">
        <dt className="text-arena-muted">Action</dt>
        <dd className={active ? 'font-medium text-arena-green' : 'text-arena-muted'}>
          {defense.action}
        </dd>
      </div>
      <div className="flex justify-between gap-2">
        <dt className="text-arena-muted">Rule</dt>
        <dd className="font-mono-telemetry text-xs text-arena-text">{defense.trigger_rule || '—'}</dd>
      </div>
      <div className="flex justify-between gap-2">
        <dt className="text-arena-muted">Target IP</dt>
        <dd className="font-mono-telemetry text-xs text-arena-text">{defense.target_ip || '—'}</dd>
      </div>
      <div className="flex justify-between gap-2">
        <dt className="text-arena-muted">Endpoint</dt>
        <dd className="font-mono-telemetry text-xs text-arena-text">{defense.target_endpoint || '—'}</dd>
      </div>
    </dl>
  )

  if (embedded) return <div className="text-left">{inner}</div>

  return (
    <section className="rounded-lg border border-arena-border bg-arena-surface p-4 text-left shadow-sm">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-arena-muted">
        Last defense (blue)
      </h2>
      {inner}
    </section>
  )
}
