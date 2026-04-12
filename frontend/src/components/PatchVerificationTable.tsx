import type { PatchRecord } from '../types/arena'

interface Props {
  records: PatchRecord[]
}

/** Dense academic table for patch verification status. */
export function PatchVerificationTable({ records }: Props) {
  if (records.length === 0) {
    return (
      <p className="text-sm text-arena-muted">
        No patch records yet. After an episode ends, verified patches appear here.
      </p>
    )
  }

  const sorted = [...records].sort((a, b) => {
    if (a.verified !== b.verified) return a.verified ? -1 : 1
    return 0
  })

  return (
    <div className="overflow-x-auto rounded-lg border border-arena-border bg-arena-surface shadow-sm">
      <table className="w-full border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-arena-border bg-arena-table-header text-xs font-semibold uppercase tracking-wide text-arena-muted">
            <th className="px-3 py-2">Vulnerability</th>
            <th className="px-3 py-2">Endpoint</th>
            <th className="px-3 py-2">CWE</th>
            <th className="px-3 py-2">Verified</th>
            <th className="px-3 py-2">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((p, idx) => (
            <tr key={`${p.endpoint}-${p.vulnerability_name}-${idx}`} className="border-b border-arena-border/90">
              <td className="px-3 py-2 font-medium text-arena-text">{p.vulnerability_name}</td>
              <td className="px-3 py-2 font-mono-telemetry text-xs text-arena-text">{p.endpoint}</td>
              <td className="px-3 py-2 font-mono-telemetry text-xs text-arena-muted">{p.cwe}</td>
              <td className="px-3 py-2">
                <span
                  className={
                    p.verified ? 'font-semibold text-arena-green' : 'font-semibold text-arena-red'
                  }
                >
                  {p.verified ? 'yes' : 'no'}
                </span>
                {p.requires_human_review ? (
                  <span className="ml-2 text-xs text-arena-orange">(review)</span>
                ) : null}
              </td>
              <td className="max-w-xs truncate px-3 py-2 font-mono-telemetry text-xs text-arena-muted" title={p.verification_evidence}>
                {p.verification_evidence}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
