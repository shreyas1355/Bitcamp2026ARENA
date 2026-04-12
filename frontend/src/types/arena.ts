/** Mirrors backend state + WebSocket payloads (PROMPT.md §9–10). */

export interface AttackEvent {
  type: string
  target: string
  payload: string
  result: string
  evidence: string
  cwe: string
  severity: string
  timestamp: number
}

export interface DefenseEvent {
  action: string
  trigger_rule: string
  target_ip: string
  target_endpoint: string
  timestamp: number
}

export interface LLMDecision {
  technique: string
  target_endpoint: string
  method: string
  params: Record<string, string>
  headers: Record<string, string>
  payload: Record<string, unknown>
  rationale: string
  attack_layer: number
}

export interface PatchRecord {
  vulnerability_name: string
  cwe: string
  endpoint: string
  patch_code: string
  patch_applied: boolean
  verification_payload: string
  verified: boolean
  verification_evidence: string
  requires_human_review: boolean
}

export interface SupervisorReport {
  risk_score: number
  vulnerabilities: Array<Record<string, unknown>>
  mitigations: string[]
  next_episode_strategy: string
  episode_summary: string
  token_count: number
}

/** GET /state */
export interface StateSnapshot {
  episode: number
  step: number
  risk_score: number
  risk_history: number[]
  blocked_ips: string[]
  active_mitigations: Record<string, boolean>
  vulnerabilities_found: unknown[]
  supervisor_report: SupervisorReport | null
  last_attack: AttackEvent | null
  last_defense: DefenseEvent | null
  current_attack_layer: number
  patch_records: PatchRecord[]
  llm_decision: LLMDecision | null
}

export interface StepUpdateMessage {
  type: 'step_update'
  episode: number
  step: number
  risk_score: number
  risk_history: number[]
  last_attack: AttackEvent | null
  last_defense: DefenseEvent | null
  active_mitigations: Record<string, boolean>
  vulnerabilities_found: unknown[]
  llm_decision: LLMDecision | null
}

export interface EpisodeReportMessage {
  type: 'episode_report'
  episode: number
  report: Record<string, unknown>
}

export interface PatchSummaryPatch {
  vulnerability: string
  endpoint: string
  cwe: string
  verified: boolean
  requires_human_review: boolean
  evidence: string
}

export interface PatchSummaryMessage {
  type: 'patch_summary'
  episode: number
  patches: PatchSummaryPatch[]
}

export type WsMessage = StepUpdateMessage | EpisodeReportMessage | PatchSummaryMessage
