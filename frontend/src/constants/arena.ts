/** Mirrors backend/config.py MAX_STEPS for progress UI. */
export const MAX_STEPS_PER_EPISODE = 50

/** Target routes the red team can hit (aligned with backend/target/router.py). */
export const TARGET_ENDPOINTS = ['/login', '/data', '/admin', '/transfer', '/files'] as const

export type TargetEndpoint = (typeof TARGET_ENDPOINTS)[number]
