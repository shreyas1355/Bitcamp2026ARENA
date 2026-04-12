interface Props {
  items: unknown[]
}

export function VulnerabilitiesPanel({ items }: Props) {
  return (
    <section className="rounded-lg border border-arena-border bg-arena-surface p-4 text-left shadow-sm">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-arena-muted">
        Vulnerabilities found
      </h2>
      {items.length === 0 ? (
        <p className="text-sm text-arena-muted">None recorded this episode.</p>
      ) : (
        <ul className="max-h-48 space-y-2 overflow-y-auto text-sm">
          {items.map((v, i) => (
            <li
              key={i}
              className="rounded border border-arena-border bg-arena-bg px-2 py-1.5 font-mono-telemetry text-xs text-arena-text"
            >
              {typeof v === 'string' ? v : JSON.stringify(v)}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
