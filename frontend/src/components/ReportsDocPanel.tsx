import type { PatchRecord } from '../types/arena'
import { PatchVerificationTable } from './PatchVerificationTable'

interface Props {
  reportsByEpisode: Record<number, Record<string, unknown>>
  patchRecords: PatchRecord[]
}

/**
 * Full-page reports: per-episode supervisor payloads + cumulative patch table.
 */
export function ReportsDocPanel({ reportsByEpisode, patchRecords }: Props) {
  const episodes = Object.keys(reportsByEpisode)
    .map(Number)
    .sort((a, b) => b - a)

  return (
    <div className="space-y-8">
      <section>
        <h2 className="mb-3 font-serif text-lg font-semibold text-arena-text">Supervisor by episode</h2>
        {episodes.length === 0 ? (
          <p className="text-sm text-arena-muted">No completed supervisor reports in this session yet.</p>
        ) : (
          <div className="space-y-6">
            {episodes.map((ep) => (
              <article key={ep} className="rounded-lg border border-arena-border bg-arena-surface p-4 shadow-sm">
                <h3 className="mb-2 font-mono-telemetry text-sm font-semibold text-arena-text">Episode {ep}</h3>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded border border-arena-border bg-arena-bg p-3 font-mono-telemetry text-xs leading-relaxed text-arena-text">
                  {JSON.stringify(reportsByEpisode[ep], null, 2)}
                </pre>
              </article>
            ))}
          </div>
        )}
      </section>
      <section>
        <h2 className="mb-3 font-serif text-lg font-semibold text-arena-text">Patch verifications (cumulative)</h2>
        <PatchVerificationTable records={patchRecords} />
      </section>
    </div>
  )
}
