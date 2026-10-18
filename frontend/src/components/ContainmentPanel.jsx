import { Section, Empty, PathText } from './ui'

const actionKey = (a) =>
  a.action_type === 'block_connection' ? `edge:${a.source}->${a.target}` : `iso:${a.target_device}`

function Metric({ label, before, after, suffix = '' }) {
  return (
    <div className="flex justify-between py-1 text-xs">
      <span className="text-zinc-500">{label}</span>
      <span className="font-mono">
        <span className="text-zinc-400">{before}{suffix}</span>
        <span className="mx-1.5 text-zinc-600">→</span>
        <span className="text-zinc-100">{after}{suffix}</span>
      </span>
    </div>
  )
}

export default function ContainmentPanel({
  containment, impact, enabled, toggleAction, names, focus, setFocus, view, setView, simulating,
}) {
  if (!containment) return null
  const actions = containment.recommended_actions || []

  return (
    <>
      <Section title="Recommended containment">
        {actions.length === 0 ? (
          <Empty>{containment.message || 'No containment actions needed.'}</Empty>
        ) : (
          <ul className="space-y-1.5">
            {actions.map((a) => {
              const key = actionKey(a)
              const target =
                a.action_type === 'block_connection'
                  ? <PathText path={[a.source, a.target]} names={names} />
                  : <span className="font-mono text-[11px] text-zinc-400">{names[a.target_device] || a.target_device}</span>
              return (
                <li
                  key={key}
                  className={`flex gap-2 rounded px-2 py-1.5 ${focus?.key === key ? 'bg-sky-500/10' : 'hover:bg-white/[0.03]'}`}
                >
                  <input
                    type="checkbox"
                    checked={enabled.has(key)}
                    onChange={() => toggleAction(key)}
                    className="mt-0.5 accent-sky-500"
                    title="Include in simulation"
                  />
                  <div
                    className="flex-1 cursor-pointer"
                    onClick={() =>
                      setFocus(
                        a.action_type === 'block_connection'
                          ? { key, edge: `${a.source}->${a.target}` }
                          : { key, node: a.target_device },
                      )
                    }
                  >
                    <div className="flex justify-between text-xs">
                      <span className="text-zinc-200">
                        {a.action_type === 'block_connection' ? 'Block connection' : 'Isolate device'}
                      </span>
                      <span className="font-mono text-zinc-500">cost {a.cost}</span>
                    </div>
                    {target}
                    <div className="text-[11px] text-emerald-400/80">
                      Protects: {(a.protected_assets || []).map((id) => names[id] || id).join(', ') || '—'}
                    </div>
                  </div>
                </li>
              )
            })}
          </ul>
        )}
        {containment.explanation && <p className="mt-2 text-[11px] text-zinc-500">{containment.explanation}</p>}
      </Section>

      <Section
        title="Before / after"
        right={
          <div className="flex overflow-hidden rounded border border-white/10 text-[11px]">
            {['original', 'contained'].map((v) => (
              <button
                key={v}
                onClick={() => setView(v)}
                disabled={!impact}
                className={`px-2 py-0.5 capitalize ${view === v ? 'bg-white/10 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300'}`}
              >
                {v}
              </button>
            ))}
          </div>
        }
      >
        {simulating && <Empty>Simulating…</Empty>}
        {!simulating && impact && (
          <>
            <Metric label="Reachable devices" before={impact.original_reachable_devices.length - 1} after={impact.remaining_reachable_devices.length - 1} />
            <Metric label="Critical assets exposed" before={impact.original_exposed_critical_assets.length} after={impact.remaining_exposed_critical_assets.length} />
            <Metric label="Aggregate risk" before={impact.original_total_risk_score} after={impact.remaining_total_risk_score} />
            <div className="flex justify-between py-1 text-xs">
              <span className="text-zinc-500">Risk reduction</span>
              <span className="font-mono text-emerald-400">
                {impact.absolute_risk_reduction} ({impact.percentage_risk_reduction}%)
              </span>
            </div>
            <div className="flex justify-between py-1 text-xs">
              <span className="text-zinc-500">Disruption cost</span>
              <span className="font-mono text-zinc-300">{impact.total_disruption_cost}</span>
            </div>
            <div className="mt-2 text-[11px]">
              <span className="text-zinc-500">Still exposed: </span>
              {impact.remaining_exposed_critical_assets.length === 0 ? (
                <span className="text-emerald-400/80">none</span>
              ) : (
                <span className="text-red-300/80">
                  {impact.remaining_exposed_critical_assets.map((id) => names[id] || id).join(', ')}
                </span>
              )}
            </div>
          </>
        )}
      </Section>
    </>
  )
}
