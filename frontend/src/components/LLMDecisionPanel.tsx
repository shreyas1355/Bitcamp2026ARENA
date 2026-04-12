import type { LLMDecision } from '../types/arena'

interface Props {
  decision: LLMDecision | null
  embedded?: boolean
}

export function LLMDecisionPanel({ decision, embedded }: Props) {
  const inner = !decision ? (
    <p className="text-sm text-arena-muted">No LLM decision yet.</p>
  ) : (
    <div className="space-y-3 text-sm">
      <div className="flex flex-wrap gap-2">
        <span className="rounded border border-arena-border bg-arena-muted-bg px-2 py-0.5 font-mono-telemetry text-xs text-arena-text">
          {decision.technique}
        </span>
        <span className="text-arena-muted">{decision.method}</span>
        <span className="font-mono-telemetry text-arena-text">{decision.target_endpoint}</span>
      </div>
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-arena-muted">Rationale</p>
        <p className="mt-1 leading-relaxed text-arena-text">{decision.rationale}</p>
      </div>
      <details className="text-xs">
        <summary className="cursor-pointer text-arena-accent hover:underline">Payload / params</summary>
        <pre className="mt-2 max-h-32 overflow-auto rounded border border-arena-border bg-arena-bg p-2 font-mono-telemetry text-[11px] text-arena-text">
          {JSON.stringify({ params: decision.params, payload: decision.payload }, null, 2)}
        </pre>
      </details>
    </div>
  )

  if (embedded) return <div className="text-left">{inner}</div>

  return (
    <section className="rounded-lg border border-arena-border bg-arena-surface p-4 text-left shadow-sm">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-arena-muted">
        Red strategist (Ollama)
      </h2>
      {inner}
    </section>
  )
}
