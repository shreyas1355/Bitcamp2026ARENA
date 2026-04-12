interface Props {
  episode: number
  step: number
  attackLayer: number
  wsConnected: boolean
}

export function ArenaHeader({ episode, step, attackLayer, wsConnected }: Props) {
  return (
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-arena-border pb-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-arena-text">
          ACDA — Autonomous Cyber Defense Arena
        </h1>
        <p className="text-sm text-arena-muted">
          Episode {episode} · Step {step} · Attack layer {attackLayer}
        </p>
      </div>
      <div
        className={`rounded-full px-3 py-1 text-xs font-medium ${
          wsConnected
            ? 'bg-arena-green/20 text-arena-green'
            : 'bg-arena-red/20 text-arena-red'
        }`}
        title="WebSocket /ws"
      >
        {wsConnected ? 'Live' : 'Disconnected'}
      </div>
    </header>
  )
}
