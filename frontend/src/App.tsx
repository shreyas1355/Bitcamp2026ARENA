import { useArenaSocket } from './hooks/useArenaSocket'
import { ArenaHeader } from './components/ArenaHeader'
import { RiskGauge } from './components/RiskGauge'
import { AttackPanel } from './components/AttackPanel'
import { DefensePanel } from './components/DefensePanel'
import { LLMDecisionPanel } from './components/LLMDecisionPanel'
import { MitigationsPanel } from './components/MitigationsPanel'
import { VulnerabilitiesPanel } from './components/VulnerabilitiesPanel'
import { ReportPanel } from './components/ReportPanel'

function App() {
  const {
    snapshot,
    loadError,
    wsConnected,
    wsError,
    episodeReport,
    lastPatchSummary,
  } = useArenaSocket()

  if (loadError && !snapshot) {
    return (
      <div className="min-h-screen bg-arena-bg p-6 text-arena-text">
        <p className="text-arena-red">Failed to load arena: {loadError}</p>
        <p className="mt-2 text-sm text-arena-muted">
          Is the API running at {import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:8000'}?
        </p>
      </div>
    )
  }

  if (!snapshot) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-arena-bg text-arena-muted">
        Loading arena state…
      </div>
    )
  }

  const s = snapshot

  return (
    <div className="min-h-screen bg-arena-bg text-arena-text">
      <div className="mx-auto max-w-7xl px-4 py-6">
        <ArenaHeader
          episode={s.episode}
          step={s.step}
          attackLayer={s.current_attack_layer ?? 1}
          wsConnected={wsConnected}
        />

        {wsError && (
          <p className="mt-2 text-sm text-arena-orange">{wsError}</p>
        )}

        <div className="mt-6 grid gap-4 lg:grid-cols-2">
          <RiskGauge riskScore={s.risk_score} riskHistory={s.risk_history ?? []} />
          <MitigationsPanel
            mitigations={s.active_mitigations ?? {}}
            blockedIps={s.blocked_ips ?? []}
          />
          <AttackPanel attack={s.last_attack} />
          <DefensePanel defense={s.last_defense} />
          <LLMDecisionPanel decision={s.llm_decision} />
          <VulnerabilitiesPanel items={s.vulnerabilities_found ?? []} />
        </div>

        <div className="mt-6">
          <ReportPanel
            supervisorReport={s.supervisor_report}
            episodeReport={episodeReport}
            patchRecords={s.patch_records ?? []}
            lastPatchSummary={lastPatchSummary}
          />
        </div>
      </div>
    </div>
  )
}

export default App
