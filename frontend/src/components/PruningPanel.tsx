import type { PruneRemovedEntry } from '../types/arena'

interface Props {
  entries: PruneRemovedEntry[]
}

/**
 * SEMA observation pruning: attributes dropped last step with δH scores.
 */
export function PruningPanel({ entries }: Props) {
  return (
    <section className="rounded-lg border border-arena-border bg-arena-surface p-4 text-left shadow-sm">
      <h2 className="mb-1 font-serif text-lg font-semibold text-arena-text">SEMA prune (last step)</h2>
      <p className="mb-3 text-xs text-arena-muted">
        Low-entropy attributes removed before LLM / supervisor (Algorithm 1, arXiv:2603.23875).
      </p>
      {entries.length === 0 ? (
        <p className="text-sm text-arena-muted">No attributes pruned this step.</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {entries.map((row, idx) => (
            <span
              key={row.attribute ?? `row-${idx}`}
              className="rounded bg-arena-table-header px-2 py-1 font-mono-telemetry text-xs text-arena-muted"
            >
              {String(row.attribute ?? '—')}
            </span>
          ))}
        </div>
      )}
    </section>
  )
}
