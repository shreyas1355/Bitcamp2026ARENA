import type { StateSnapshot } from '../types/arena'

export function getApiBase(): string {
  return import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:8000'
}

export function getWsUrl(): string {
  const base = getApiBase()
  const u = new URL(base)
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:'
  u.pathname = '/ws'
  u.search = ''
  u.hash = ''
  return u.toString()
}

export async function fetchState(): Promise<StateSnapshot> {
  const res = await fetch(`${getApiBase()}/state`)
  if (!res.ok) {
    throw new Error(`GET /state failed: ${res.status}`)
  }
  return res.json() as Promise<StateSnapshot>
}
