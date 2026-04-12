import { MAX_STEPS_PER_EPISODE } from '../constants/arena'

interface Props {
  episode: number
  step: number
  wsConnected: boolean
  viewEpisode: number | 'live'
}

export function ArenaHeader({
  episode,
  step,
  wsConnected,
  viewEpisode,
}: Props) {
  const viewing =
    viewEpisode === 'live' ? null : (
      <span className="ml-2 rounded border border-arena-orange/40 bg-arena-orange/10 px-2 py-0.5 text-xs font-medium text-arena-orange">
        Viewing episode {viewEpisode} (buffered)
      </span>
    )

  return (
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-arena-border pb-4">
      <div>
        <h1 className="font-serif text-2xl font-semibold tracking-tight text-arena-text">arena</h1>
        <p className="mt-1 text-sm text-arena-muted">
          Autonomous attack, defense, and verified patching — Episode {episode} · Step {step} /{' '}
          {MAX_STEPS_PER_EPISODE}
          {viewing}
        </p>
      </div>
      <div
        className={`rounded-full border px-3 py-1 text-xs font-medium ${
          wsConnected
            ? 'border-arena-green/40 bg-arena-green-soft text-arena-green'
            : 'border-arena-red/40 bg-arena-red-soft text-arena-red'
        }`}
        title="WebSocket /ws"
      >
        {wsConnected ? 'Live' : 'Disconnected'}
      </div>
    </header>
  )
}
