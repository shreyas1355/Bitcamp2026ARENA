interface Props {
  items: unknown[]
}

export function VulnerabilitiesPanel({ items }: Props) {
  return (
    <section className="rounded-lg border border-arena-border bg-arena-surface p-4 text-left">
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-arena-muted">
        Vulnerabilities found
      </h2>
      {items.length === 0 ? (
        <p className="text-sm text-arena-muted">None recorded this episode.</p>
      ) : (
        <ul className="max-h-40 space-y-2 overflow-y-auto text-sm">
          {items.map((v, i) => (
            <li
              key={i}
              className="rounded border border-arena-border bg-arena-bg/50 px-2 py-1 font-mono text-xs"
            >
              {typeof v === 'string' ? v : JSON.stringify(v)}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
