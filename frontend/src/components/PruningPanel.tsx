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
        Low-δH attributes removed before LLM / supervisor (Algorithm 1). δH = α·ΔH_G + β·ΔH_T per attribute.
      </p>
      {entries.length === 0 ? (
        <p className="text-sm text-arena-muted">No attributes pruned this step (telemetry unchanged or graph degenerate).</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-arena-border bg-arena-table-header text-xs font-semibold uppercase tracking-wide text-arena-muted">
                <th className="px-3 py-2">Attribute</th>
                <th className="px-3 py-2">δH (removed)</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((row, idx) => {
                const raw = row.delta_h
                const n = typeof raw === 'number' ? raw : Number(raw)
                const cell = Number.isFinite(n) ? n.toFixed(5) : String(raw ?? '—')
                return (
                  <tr key={row.attribute ?? `row-${idx}`} className="border-b border-arena-border/80">
                    <td className="px-3 py-1.5 font-mono-telemetry text-arena-text">{String(row.attribute ?? '—')}</td>
                    <td className="px-3 py-1.5 font-mono-telemetry text-arena-muted">{cell}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
