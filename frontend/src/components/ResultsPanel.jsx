import { Section, Empty, Table, Row, PathText } from './ui'

export default function ResultsPanel({ analysis, risk, critical, names, focus, setFocus }) {
  if (!analysis) return null
  const others = analysis.reachable_devices.filter((d) => d !== analysis.compromised_device)

  return (
    <>
      <Section title={`Reachable devices (${others.length})`}>
        {others.length === 0 ? (
          <Empty>No devices reachable through allowed connections.</Empty>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {others.map((id) => (
              <button
                key={id}
                onClick={() => setFocus({ key: `node:${id}`, node: id })}
                className={`rounded px-2 py-0.5 text-xs ${focus?.key === `node:${id}` ? 'bg-sky-500/20 text-sky-200' : 'bg-white/5 text-zinc-300 hover:bg-white/10'}`}
              >
                {names[id] || id}
              </button>
            ))}
          </div>
        )}
      </Section>

      <Section title={`Critical assets exposed (${critical?.count ?? 0})`}>
        {!critical || critical.count === 0 ? (
          <Empty>No assets at or above criticality {critical?.threshold ?? 4} are reachable.</Empty>
        ) : (
          <ul className="space-y-1.5">
            {critical.critical_assets.map((a) => {
              const key = `path:${a.device_id}`
              return (
                <li
                  key={a.device_id}
                  onClick={() => setFocus({ key, path: a.path })}
                  className={`cursor-pointer rounded px-2 py-1.5 ${focus?.key === key ? 'bg-sky-500/10' : 'hover:bg-white/[0.03]'}`}
                >
                  <div className="flex justify-between text-xs">
                    <span className="text-zinc-200">{a.name}</span>
                    <span className="font-mono text-amber-300/80">C{a.criticality} · {a.hops} hop{a.hops > 1 ? 's' : ''}</span>
                  </div>
                  <PathText path={a.path} names={names} />
                </li>
              )
            })}
          </ul>
        )}
      </Section>

      <Section title="Risk ranking">
        {!risk || risk.results.length === 0 ? (
          <Empty>No exposed devices to rank.</Empty>
        ) : (
          <>
            <Table head={['Device', 'Crit.', 'Hops', 'Score']}>
              {risk.results.map((r) => {
                const key = `path:${r.device_id}`
                return (
                  <Row
                    key={r.device_id}
                    active={focus?.key === key}
                    onClick={() => setFocus({ key, path: r.path })}
                    cells={[r.name, r.criticality, r.hops, r.risk_score.toFixed(1)]}
                  />
                )
              })}
            </Table>
            <p className="mt-2 text-[10px] text-zinc-600">
              Heuristic score = criticality/5 × 100 ÷ hops. Not an attack probability.
            </p>
          </>
        )}
      </Section>
    </>
  )
}
