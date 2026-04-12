import type { PatchRecord, PatchSummaryMessage } from '../types/arena'

/** Prefer full /state records; if empty, show rows from last WebSocket patch_summary. */
export function mergePatchRecords(
  records: PatchRecord[] | undefined,
  summary: PatchSummaryMessage | null,
): PatchRecord[] {
  const r = Array.isArray(records) ? records : []
  if (r.length > 0) return r
  if (!summary?.patches?.length) return []
  const patches = Array.isArray(summary.patches) ? summary.patches : []
  return patches.map((p) => ({
    vulnerability_name: p.vulnerability,
    cwe: p.cwe,
    endpoint: p.endpoint,
    patch_code: '',
    patch_applied: true,
    verification_payload: '',
    verified: p.verified,
    verification_evidence: p.evidence,
    requires_human_review: p.requires_human_review,
  }))
}
