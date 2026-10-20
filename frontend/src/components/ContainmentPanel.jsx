import { Section, Empty } from './ui'

const actionKey = (a) =>
  a.action_type === 'block_connection' ? `edge:${a.source}->${a.target}` : `iso:${a.target_device}`

function ComparisonRow({ label, before, after, unit = '' }) {
  const isBetter = before > after
  const isWorse = after > before
  const changeTone = isBetter ? 'text-ok' : isWorse ? 'text-danger' : 'text-fg-subtle'

  return (
    <div className="flex items-center justify-between py-1 text-xs border-b border-line/50 last:border-0">
      <span className="text-fg-subtle">{label}</span>
      <div className="flex items-center gap-2 font-mono text-[11px]">
        <span className="text-fg-muted">{before}{unit}</span>
        <span className="text-fg-subtle">→</span>
        <span className={`font-semibold ${changeTone}`}>
          {after}{unit}
        </span>
      </div>
    </div>
  )
}

export default function ContainmentPanel({
  containment,
  impact,
  enabled,
  toggleAction,
  names,
  focus,
  setFocus,
  view,
  setView,
  simulating,
}) {
  if (!containment) return null
  const actions = containment.recommended_actions || []

  return (
    <div className="space-y-1 border-t border-line">
      {/* ---------------------------------------------------------------------
          4. RECOMMENDED CONTAINMENT ACTIONS
      --------------------------------------------------------------------- */}
      <Section
        title="Containment Recommendations"
        count={actions.length}
        collapsible
        defaultOpen={true}
        right={
          actions.length > 0 ? (
            <span className="text-[10px] text-fg-subtle">
              {enabled.size} of {actions.length} enabled
            </span>
          ) : null
        }
      >
        {actions.length === 0 ? (
          <Empty>{containment.message || 'No containment actions required.'}</Empty>
        ) : (
          <div className="space-y-1.5">
            {actions.map((a) => {
              const key = actionKey(a)
              const isChecked = enabled.has(key)
              const isSelected = focus?.key === key

              return (
                <div
                  key={key}
                  className={`flex items-start gap-2.5 rounded-md border p-2 transition-colors ${
                    isSelected
                      ? 'border-accent bg-accent/5 ring-1 ring-accent/30'
                      : 'border-line bg-s2/40 hover:bg-s2/80'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={isChecked}
                    onChange={() => toggleAction(key)}
                    className="mt-1 accent-accent cursor-pointer"
                    title="Toggle action in simulation"
                  />

                  <div
                    className="flex-1 cursor-pointer min-w-0"
                    onClick={() =>
                      setFocus(
                        a.action_type === 'block_connection'
                          ? { key, edge: `${a.source}->${a.target}` }
                          : { key, node: a.target_device },
                      )
                    }
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`badge ${
                            a.action_type === 'block_connection' ? 'badge-warn' : 'badge-danger'
                          }`}
                        >
                          {a.action_type === 'block_connection' ? 'Block Link' : 'Isolate Device'}
                        </span>
                        <span className="mono text-xs font-semibold text-fg truncate">
                          {a.action_type === 'block_connection'
                            ? `${names[a.source] || a.source} → ${names[a.target] || a.target}`
                            : names[a.target_device] || a.target_device}
                        </span>
                      </div>
                      <span className="mono text-[10px] text-fg-subtle shrink-0">
                        Cost: {a.cost}
                      </span>
                    </div>

                    <div className="mt-1 flex items-center gap-1 text-[11px] text-ok">
                      <span className="text-fg-subtle">Protects:</span>
                      <span className="font-medium truncate">
                        {(a.protected_assets || []).map((id) => names[id] || id).join(', ') || 'Alternative path reduction'}
                      </span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Section>

      {/* ---------------------------------------------------------------------
          SIMULATION IMPACT COMPARISON (BEFORE VS. AFTER)
      --------------------------------------------------------------------- */}
      <Section
        title="Simulation Impact"
        collapsible
        defaultOpen={true}
        right={
          <div className="flex rounded border border-line bg-s2 p-0.5 text-[10px]">
            <button
              type="button"
              onClick={() => setView('original')}
              disabled={!impact}
              className={`rounded px-2 py-0.5 font-medium transition-colors ${
                view === 'original' ? 'bg-s3 text-fg' : 'text-fg-subtle hover:text-fg'
              }`}
            >
              Original
            </button>
            <button
              type="button"
              onClick={() => setView('contained')}
              disabled={!impact}
              className={`rounded px-2 py-0.5 font-medium transition-colors ${
                view === 'contained' ? 'bg-ok/20 text-ok' : 'text-fg-subtle hover:text-fg'
              }`}
            >
              Contained View
            </button>
          </div>
        }
      >
        <div className="space-y-3">
          {simulating && <Empty>Recalculating containment graph...</Empty>}

          {!simulating && impact && (
            <>
              {/* Impact Comparison Table */}
              <div className="rounded-md border border-line bg-s2/40 p-2.5">
                <ComparisonRow
                  label="Reachable Devices"
                  before={impact.original_reachable_devices.length - 1}
                  after={impact.remaining_reachable_devices.length - 1}
                />
                <ComparisonRow
                  label="Critical Assets Exposed"
                  before={impact.original_exposed_critical_assets.length}
                  after={impact.remaining_exposed_critical_assets.length}
                />
                <ComparisonRow
                  label="Attack Paths to Critical"
                  before={impact.original_attack_paths_count ?? 0}
                  after={impact.remaining_attack_paths_count ?? 0}
                />
                <ComparisonRow
                  label="Aggregate Risk Index"
                  before={impact.original_total_risk_score}
                  after={impact.remaining_total_risk_score}
                />
                <div className="flex items-center justify-between pt-1.5 text-xs">
                  <span className="text-fg-subtle">Disruption Cost</span>
                  <span className="mono font-semibold text-fg">
                    {impact.total_disruption_cost}
                  </span>
                </div>
              </div>

              {/* Status callout: Protected vs. Still Exposed */}
              <div className="rounded-md border border-line bg-s2/20 p-2.5 space-y-1 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-fg-subtle">Protected Assets:</span>
                  <span className="font-semibold text-ok">
                    {impact.protected_critical_assets?.length > 0
                      ? impact.protected_critical_assets.map((id) => names[id] || id).join(', ')
                      : 'None'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-fg-subtle">Residual Critical Exposed:</span>
                  <span className={`font-semibold ${impact.remaining_exposed_critical_assets?.length > 0 ? 'text-danger' : 'text-ok'}`}>
                    {impact.remaining_exposed_critical_assets?.length === 0
                      ? 'None (Fully Contained)'
                      : impact.remaining_exposed_critical_assets.map((id) => names[id] || id).join(', ')}
                  </span>
                </div>
              </div>

              <p className="text-[10px] text-fg-subtle italic">
                * Note: Simulation runs on an isolated in-memory graph copy. No live firewall or host policies are altered.
              </p>
            </>
          )}
        </div>
      </Section>
    </div>
  )
}
