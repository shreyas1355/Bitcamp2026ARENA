import { useState } from 'react'
import type { EpisodeReportMessage, PatchRecord, PatchSummaryMessage, SupervisorReport } from '../types/arena'

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
    <section className="rounded-lg border border-arena-border bg-arena-surface p-4 text-left">
      <div className="mb-4 flex gap-2 border-b border-arena-border pb-2">
        <button
          type="button"
          onClick={() => setTab('supervisor')}
          className={`rounded px-3 py-1 text-sm font-medium ${
            tab === 'supervisor'
              ? 'bg-arena-blue/20 text-arena-blue'
              : 'text-arena-muted hover:text-arena-text'
          }`}
        >
          Supervisor
        </button>
        <button
          type="button"
          onClick={() => setTab('patches')}
          className={`rounded px-3 py-1 text-sm font-medium ${
            tab === 'patches'
              ? 'bg-arena-blue/20 text-arena-blue'
              : 'text-arena-muted hover:text-arena-text'
          }`}
        >
          Patches
          {patchRecords.length > 0 && (
            <span className="ml-1 text-xs opacity-80">({patchRecords.length})</span>
          )}
        </button>
      </div>

      {tab === 'supervisor' && (
        <div className="max-h-96 overflow-y-auto text-sm">
          {!report ? (
            <p className="text-arena-muted">No supervisor report yet (wait for end of episode).</p>
          ) : (
            <pre className="whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-arena-text">
              {JSON.stringify(report, null, 2)}
            </pre>
          )}
        </div>
      )}

      {tab === 'patches' && (
        <PatchesTab
          patchRecords={patchRecords}
          lastPatchSummary={lastPatchSummary}
        />
      )}
    </section>
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
    <div className="max-h-[28rem] space-y-4 overflow-y-auto">
      {lastPatchSummary && lastPatchSummary.patches.length > 0 && (
        <p className="text-xs text-arena-muted">
          Latest broadcast: episode {lastPatchSummary.episode} ({lastPatchSummary.patches.length}{' '}
          patch attempt(s))
        </p>
      )}
      {patchRecords.length === 0 ? (
        <p className="text-sm text-arena-muted">
          No patch records yet. After an episode ends, verified patches appear here (with code from
          /state).
        </p>
      ) : (
        <ul className="space-y-4">
          {[...patchRecords].reverse().map((p, idx) => (
            <li
              key={`${p.endpoint}-${p.vulnerability_name}-${idx}`}
              className="rounded-lg border border-arena-border bg-arena-bg/40 p-3"
            >
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-medium text-arena-text">{p.vulnerability_name}</h3>
                <span
                  className={`rounded px-2 py-0.5 text-xs font-medium ${
                    p.verified
                      ? 'bg-arena-green/20 text-arena-green'
                      : 'bg-arena-red/20 text-arena-red'
                  }`}
                >
                  {p.verified ? '✓ Verified' : '✗ Failed / review'}
                </span>
                {p.requires_human_review && (
                  <span className="rounded bg-arena-orange/20 px-2 py-0.5 text-xs text-arena-orange">
                    Requires human review
                  </span>
                )}
              </div>
              <p className="mt-1 font-mono text-xs text-arena-muted">
                {p.cwe} · {p.endpoint}
              </p>
              <p className="mt-2 text-xs text-arena-text">{p.verification_evidence}</p>
              {p.patch_code ? (
                <details className="mt-2">
                  <summary className="cursor-pointer text-xs text-arena-blue">Generated patch code</summary>
                  <pre className="mt-2 max-h-48 overflow-auto rounded bg-arena-bg p-2 font-mono text-[11px] text-arena-text">
                    {p.patch_code}
                  </pre>
                </details>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
