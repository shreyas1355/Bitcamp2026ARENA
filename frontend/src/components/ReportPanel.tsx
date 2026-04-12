import { useState } from 'react'
import type { EpisodeReportMessage, PatchRecord, PatchSummaryMessage, SupervisorReport } from '../types/arena'
import { PatchVerificationTable } from './PatchVerificationTable'

type Tab = 'supervisor' | 'patches'

interface Props {
  supervisorReport: SupervisorReport | null
  episodeReport: EpisodeReportMessage | null
  patchRecords: PatchRecord[]
  lastPatchSummary: PatchSummaryMessage | null
}

export function ReportPanel({
  supervisorReport,
  episodeReport,
  patchRecords,
  lastPatchSummary,
}: Props) {
  const [tab, setTab] = useState<Tab>('supervisor')

  const report =
    episodeReport?.report ??
    (supervisorReport as unknown as Record<string, unknown> | null)

  return (
    <section className="rounded-lg border border-arena-border bg-arena-surface p-4 text-left shadow-sm">
      <div className="mb-4 flex gap-2 border-b border-arena-border pb-2">
        <button
          type="button"
          onClick={() => setTab('supervisor')}
          className={`rounded border px-3 py-1 text-sm font-medium ${
            tab === 'supervisor'
              ? 'border-arena-accent bg-arena-blue-soft text-arena-accent'
              : 'border-transparent text-arena-muted hover:bg-arena-muted-bg'
          }`}
        >
          Supervisor
        </button>
        <button
          type="button"
          onClick={() => setTab('patches')}
          className={`rounded border px-3 py-1 text-sm font-medium ${
            tab === 'patches'
              ? 'border-arena-accent bg-arena-blue-soft text-arena-accent'
              : 'border-transparent text-arena-muted hover:bg-arena-muted-bg'
          }`}
        >
          Patches
          {patchRecords.length > 0 && (
            <span className="ml-1 font-mono-telemetry text-xs opacity-80">({patchRecords.length})</span>
          )}
        </button>
      </div>

      {tab === 'supervisor' && (
        <div className="max-h-96 overflow-y-auto text-sm">
          {!report ? (
            <p className="text-arena-muted">No supervisor report yet (wait for end of episode).</p>
          ) : (
            <SupervisorReadable report={report} />
          )}
        </div>
      )}

      {tab === 'patches' && (
        <PatchesTab patchRecords={patchRecords} lastPatchSummary={lastPatchSummary} />
      )}
    </section>
  )
}

function SupervisorReadable({ report }: { report: Record<string, unknown> }) {
  const risk = report.risk_score
  const summary = typeof report.episode_summary === 'string' ? report.episode_summary : null
  const strategy =
    typeof report.next_episode_strategy === 'string' ? report.next_episode_strategy : null
  const mitigations = Array.isArray(report.mitigations) ? report.mitigations : []
  const vulns = Array.isArray(report.vulnerabilities) ? report.vulnerabilities : []

  return (
    <div className="space-y-4 text-arena-text">
      {typeof risk === 'number' && (
        <p>
          <span className="font-semibold text-arena-muted">Risk score:</span>{' '}
          <span className="font-mono-telemetry">{risk.toFixed(3)}</span>
        </p>
      )}
      {summary && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-arena-muted">Episode summary</p>
          <p className="mt-1 leading-relaxed">{summary}</p>
        </div>
      )}
      {strategy && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-arena-muted">Next episode strategy</p>
          <p className="mt-1 leading-relaxed">{strategy}</p>
        </div>
      )}
      {mitigations.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-arena-muted">Mitigations</p>
          <ul className="mt-1 list-inside list-disc text-arena-text">
            {mitigations.map((m, i) => (
              <li key={i}>{String(m)}</li>
            ))}
          </ul>
        </div>
      )}
      {vulns.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-arena-muted">Vulnerabilities (report)</p>
          <ul className="mt-2 space-y-2">
            {vulns.map((v, i) => (
              <li key={i} className="rounded border border-arena-border bg-arena-bg p-2 font-mono-telemetry text-xs">
                {typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)}
              </li>
            ))}
          </ul>
        </div>
      )}
      <details className="text-xs">
        <summary className="cursor-pointer text-arena-accent hover:underline">Raw JSON</summary>
        <pre className="mt-2 max-h-48 overflow-auto rounded border border-arena-border bg-arena-bg p-2 font-mono-telemetry text-[11px]">
          {JSON.stringify(report, null, 2)}
        </pre>
      </details>
    </div>
  )
}

function PatchesTab({
  patchRecords,
  lastPatchSummary,
}: {
  patchRecords: PatchRecord[]
  lastPatchSummary: PatchSummaryMessage | null
}) {
  return (
    <div className="space-y-4">
      {lastPatchSummary && lastPatchSummary.patches.length > 0 && (
        <p className="text-xs text-arena-muted">
          Latest broadcast: episode {lastPatchSummary.episode} ({lastPatchSummary.patches.length}{' '}
          patch attempt(s))
        </p>
      )}
      <PatchVerificationTable records={patchRecords} />
      {patchRecords.length > 0 && (
        <div className="space-y-3">
          <p className="text-xs font-semibold uppercase tracking-wide text-arena-muted">Generated code</p>
          {[...patchRecords].reverse().map((p, idx) =>
            p.patch_code ? (
              <details key={`code-${idx}`} className="rounded border border-arena-border bg-arena-bg">
                <summary className="cursor-pointer px-2 py-1.5 text-xs text-arena-accent hover:underline">
                  {p.vulnerability_name} — {p.endpoint}
                </summary>
                <pre className="max-h-48 overflow-auto border-t border-arena-border p-2 font-mono-telemetry text-[11px] text-arena-text">
                  {p.patch_code}
                </pre>
              </details>
            ) : null,
          )}
        </div>
      )}
    </div>
  )
}
