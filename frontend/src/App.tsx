import { useMemo, useState } from 'react'
import { useArenaSocket } from './hooks/useArenaSocket'
import { ArenaHeader } from './components/ArenaHeader'
import { RiskGauge } from './components/RiskGauge'
import { AttackPanel } from './components/AttackPanel'
import { DefensePanel } from './components/DefensePanel'
import { LLMDecisionPanel } from './components/LLMDecisionPanel'
import { MitigationsPanel } from './components/MitigationsPanel'
import { VulnerabilitiesPanel } from './components/VulnerabilitiesPanel'
import { ReportPanel } from './components/ReportPanel'
import { PatchVerificationTable } from './components/PatchVerificationTable'
import { SurfaceMapPanel } from './components/SurfaceMapPanel'
import { EpisodesPanel } from './components/EpisodesPanel'
import { ReportsDocPanel } from './components/ReportsDocPanel'
import { PruningPanel } from './components/PruningPanel'
import { MAX_STEPS_PER_EPISODE } from './constants/arena'
import { mergePatchRecords } from './utils/mergePatchRecords'

type MainTab = 'overview' | 'surface' | 'episodes' | 'reports'

function tabBtn(active: boolean, onClick: () => void, children: string) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
        active
          ? 'border-arena-accent text-arena-accent'
          : 'border-transparent text-arena-muted hover:text-arena-text'
      }`}
    >
      {children}
    </button>
  )
}

function App() {
  const [tab, setTab] = useState<MainTab>('overview')
  const {
    snapshot,
    displaySnapshot,
    loadError,
    wsConnected,
    wsError,
    episodeReport,
    lastPatchSummary,
    timeline,
    episodeNumbers,
    reportsByEpisode,
    viewEpisode,
    setViewEpisode,
  } = useArenaSocket()

  const episodeForFrames = displaySnapshot?.episode ?? 0
  const episodeStepFrames = useMemo(
    () =>
      timeline
        .filter((f) => f.episode === episodeForFrames)
        .sort((a, b) => a.step - b.step),
    [timeline, episodeForFrames],
  )

  const mergedPatchRecords = useMemo(
    () => mergePatchRecords(displaySnapshot?.patch_records, lastPatchSummary),
    [displaySnapshot, lastPatchSummary],
  )

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

  if (!snapshot || !displaySnapshot) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-arena-bg text-arena-muted">
        Loading arena state…
      </div>
    )
  }

  const s = displaySnapshot
  const liveEp = snapshot.episode
  const stepPct = Math.min(100, Math.round((s.step / MAX_STEPS_PER_EPISODE) * 100))

  return (
    <div className="min-h-screen bg-arena-bg text-arena-text">
      <div className="mx-auto max-w-7xl px-4 py-6">
        <ArenaHeader episode={s.episode} step={s.step} wsConnected={wsConnected} viewEpisode={viewEpisode} />

        {wsError && <p className="mt-2 text-sm text-arena-orange">{wsError}</p>}

        <div className="mt-2 mb-4">
          <div className="mb-1 flex justify-between text-xs text-arena-muted">
            <span>Episode progress</span>
            <span className="font-mono-telemetry">
              step {s.step} / {MAX_STEPS_PER_EPISODE}
            </span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-arena-muted-bg">
            <div
              className="h-full rounded-full bg-arena-accent transition-all duration-300"
              style={{ width: `${stepPct}%` }}
            />
          </div>
        </div>

        <nav className="mb-6 flex flex-wrap gap-1 border-b border-arena-border">
          {tabBtn(tab === 'overview', () => setTab('overview'), 'Overview')}
          {tabBtn(tab === 'surface', () => setTab('surface'), 'Surface map')}
          {tabBtn(tab === 'episodes', () => setTab('episodes'), 'Episodes')}
          {tabBtn(tab === 'reports', () => setTab('reports'), 'Reports')}
        </nav>

        {tab === 'overview' && (
          <div className="space-y-6">
            <RiskGauge
              episode={s.episode}
              riskScore={s.risk_score}
              riskHistory={s.risk_history ?? []}
              stepFrames={episodeStepFrames}
            />
            <PruningPanel entries={s.last_prune_removed ?? []} />
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-lg border border-arena-border bg-arena-surface p-4 shadow-sm">
                <h2 className="mb-3 font-serif text-lg font-semibold text-arena-red">Offense (Red)</h2>
                <AttackPanel attack={s.last_attack} embedded />
                <div className="mt-4 border-t border-arena-border pt-4">
                  <LLMDecisionPanel decision={s.llm_decision} embedded />
                </div>
              </div>
              <div className="rounded-lg border border-arena-border bg-arena-surface p-4 shadow-sm">
                <h2 className="mb-3 font-serif text-lg font-semibold text-arena-blue">Defense (Blue)</h2>
                <DefensePanel defense={s.last_defense} embedded />
                <div className="mt-4 border-t border-arena-border pt-4">
                  <MitigationsPanel
                    mitigations={s.active_mitigations ?? {}}
                    blockedIps={s.blocked_ips ?? []}
                    embedded
                  />
                </div>
              </div>
            </div>
            <div className="grid gap-4 lg:grid-cols-2">
              <VulnerabilitiesPanel items={s.vulnerabilities_found ?? []} />
              <div className="rounded-lg border border-arena-border bg-arena-surface p-4 shadow-sm">
                <h2 className="mb-3 font-serif text-lg font-semibold text-arena-text">Patch verifications</h2>
                <PatchVerificationTable records={mergedPatchRecords} />
              </div>
            </div>
            <ReportPanel
              supervisorReport={s.supervisor_report}
              episodeReport={episodeReport}
              patchRecords={mergedPatchRecords}
              lastPatchSummary={lastPatchSummary}
            />
          </div>
        )}

        {tab === 'surface' && snapshot && (
          <SurfaceMapPanel timeline={timeline} liveEpisode={liveEp} viewEpisode={viewEpisode} />
        )}

        {tab === 'episodes' && (
          <EpisodesPanel
            episodeNumbers={episodeNumbers}
            timeline={timeline}
            viewEpisode={viewEpisode}
            liveEpisode={liveEp}
            liveStep={snapshot.step}
            onSelect={setViewEpisode}
          />
        )}

        {tab === 'reports' && (
          <ReportsDocPanel reportsByEpisode={reportsByEpisode} patchRecords={mergedPatchRecords} />
        )}
      </div>
    </div>
  )
}

export default App
