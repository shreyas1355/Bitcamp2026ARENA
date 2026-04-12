import type { LLMDecision } from '../types/arena'

interface Props {
  decision: LLMDecision | null
}

export function LLMDecisionPanel({ decision }: Props) {
  return (
    <section className="rounded-lg border border-arena-border bg-arena-surface p-4 text-left">
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-arena-muted">
        Red strategist (Ollama)
      </h2>
      {!decision ? (
        <p className="text-sm text-arena-muted">No LLM decision yet.</p>
      ) : (
        <div className="space-y-3 text-sm">
          <div className="flex flex-wrap gap-2">
            <span className="rounded bg-arena-purple/20 px-2 py-0.5 font-mono text-xs text-arena-purple">
              {decision.technique}
            </span>
            <span className="text-arena-muted">{decision.method}</span>
            <span className="font-mono text-arena-text">{decision.target_endpoint}</span>
          </div>
          <div>
            <p className="text-xs font-medium uppercase text-arena-muted">Rationale</p>
            <p className="mt-1 leading-relaxed text-arena-text">{decision.rationale}</p>
          </div>
          <details className="text-xs">
            <summary className="cursor-pointer text-arena-muted">Payload / params</summary>
            <pre className="mt-2 max-h-32 overflow-auto rounded bg-arena-bg p-2 font-mono text-[11px]">
              {JSON.stringify({ params: decision.params, payload: decision.payload }, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </section>
  )
}
