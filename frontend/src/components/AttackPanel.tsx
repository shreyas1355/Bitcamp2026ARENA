import type { AttackEvent } from '../types/arena'

function resultColor(result: string | undefined) {
  if (result === 'success') return 'text-arena-green'
  if (result === 'blocked' || result === 'rate_limited') return 'text-arena-orange'
  return 'text-arena-red'
}

interface Props {
  attack: AttackEvent | null
  /** When true, no outer card chrome (parent provides border + title). */
  embedded?: boolean
}

export function AttackPanel({ attack, embedded }: Props) {
  const inner = !attack ? (
    <p className="text-sm text-arena-muted">No attack yet.</p>
  ) : (
    <dl className="grid gap-2 text-sm">
      <div className="flex justify-between gap-2">
        <dt className="text-arena-muted">Type</dt>
        <dd className="font-mono-telemetry text-arena-text">{attack.type}</dd>
      </div>
      <div className="flex justify-between gap-2">
        <dt className="text-arena-muted">Target</dt>
        <dd className="font-mono-telemetry text-arena-text">{attack.target}</dd>
      </div>
      <div className="flex justify-between gap-2">
        <dt className="text-arena-muted">Result</dt>
        <dd className={`font-medium ${resultColor(attack.result)}`}>{attack.result}</dd>
      </div>
      <div className="flex justify-between gap-2">
        <dt className="text-arena-muted">Severity</dt>
        <dd className="text-arena-text">{attack.severity}</dd>
      </div>
      <div className="mt-2 border-t border-arena-border pt-2">
        <dt className="text-arena-muted">Evidence</dt>
        <dd className="mt-1 break-words font-mono-telemetry text-xs text-arena-text">{attack.evidence}</dd>
      </div>
    </dl>
  )

  if (embedded) return <div className="text-left">{inner}</div>

  return (
    <section className="rounded-lg border border-arena-border bg-arena-surface p-4 text-left shadow-sm">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-arena-muted">
        Last attack (red)
      </h2>
      {inner}
    </section>
  )
}
