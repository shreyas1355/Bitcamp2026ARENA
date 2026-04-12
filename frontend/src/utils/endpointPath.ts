import { TARGET_ENDPOINTS } from '../constants/arena'

/**
 * Map attack/defense target strings to a canonical endpoint path for the surface graph.
 */
export function normalizeTargetEndpoint(raw: string | undefined | null): string | null {
  if (!raw) return null
  const s = raw.trim()
  let path = s
  try {
    if (s.startsWith('http://') || s.startsWith('https://')) {
      const u = new URL(s)
      path = u.pathname
    }
  } catch {
    /* keep path as s */
  }
  path = path.replace(/^\/target(\/|$)/, '/').replace(/^\/?/, '/')
  if (!path.startsWith('/')) path = `/${path}`
  path = path.split('?')[0] ?? path
  for (const ep of TARGET_ENDPOINTS) {
    if (path === ep || path.endsWith(ep)) return ep
  }
  for (const ep of TARGET_ENDPOINTS) {
    if (path.includes(ep)) return ep
  }
  return null
}
