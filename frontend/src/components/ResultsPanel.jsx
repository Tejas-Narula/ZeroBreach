import { useState } from 'react'
import { Section, Empty, Table, Row, PathText } from './ui'

export default function ResultsPanel({ analysis, risk, critical, services, attackPaths, names, focus, setFocus }) {
  if (!analysis) return null
  const others = analysis.reachable_devices.filter((d) => d !== analysis.compromised_device)

  const [expandedPathId, setExpandedPathId] = useState(null)
  const [showOnlyExploitable, setShowOnlyExploitable] = useState(false)

  const paths = attackPaths?.attack_paths || []
  const filteredPaths = showOnlyExploitable
    ? paths.filter((p) => p.vulnerabilities_exploitable_count > 0)
    : paths

  const reachableServicesList = (services?.reachable_services || []).filter((s) => s.reachable)

  return (
    <>
      {/* VULNERABILITY-BASED ATTACK PATHS SECTION */}
      <Section title={`Attack Paths to Critical Assets (${paths.length})`}>
        {paths.length === 0 ? (
          <Empty>No attack paths found to critical assets above threshold.</Empty>
        ) : (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-[11px] text-zinc-400 pb-1 border-b border-white/5">
              <span>Origin: <strong className="text-zinc-200">{names[analysis.compromised_device] || analysis.compromised_device}</strong></span>
              <label className="flex items-center gap-1.5 cursor-pointer text-zinc-300">
                <input
                  type="checkbox"
                  checked={showOnlyExploitable}
                  onChange={(e) => setShowOnlyExploitable(e.target.checked)}
                  className="accent-red-500 rounded"
                />
                <span>Known Exploits Only</span>
              </label>
            </div>

            {filteredPaths.map((p) => {
              const isSelected = focus?.key === `path:${p.path_id}`
              const isExpanded = expandedPathId === p.path_id

              return (
                <div
                  key={p.path_id}
                  className={`rounded border transition ${
                    isSelected
                      ? 'border-sky-500/60 bg-sky-500/10'
                      : 'border-white/10 bg-white/[0.02] hover:bg-white/[0.04]'
                  }`}
                >
                  <div
                    className="p-2.5 cursor-pointer"
                    onClick={() => {
                      setFocus({ key: `path:${p.path_id}`, path: p.path })
                      setExpandedPathId(isExpanded ? null : p.path_id)
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          p.feasibility_level === 'high' ? 'bg-red-500/20 text-red-300 border border-red-500/40' :
                          p.feasibility_level === 'medium' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                          'bg-zinc-700 text-zinc-300'
                        }`}>
                          {p.feasibility_level} ({p.feasibility_score}%)
                        </span>
                        <span className="font-semibold text-xs text-zinc-100">{p.target_device_name}</span>
                      </div>
                      <span className="font-mono text-xs text-amber-300">
                        Crit: {p.target_criticality} · {p.hops_count} hop{p.hops_count > 1 ? 's' : ''}
                      </span>
                    </div>

                    <div className="mt-1.5">
                      <PathText path={p.path} names={names} />
                    </div>

                    {/* Exploit & Evidence Badges */}
                    <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[10px]">
                      {p.vulnerabilities_exploitable_count > 0 && (
                        <span className="bg-red-500/20 text-red-300 border border-red-500/30 rounded px-1.5 py-0.5">
                          ⚡ {p.vulnerabilities_exploitable_count} Known Exploit(s)
                        </span>
                      )}
                      {p.missing_or_uncertain_evidence?.length > 0 && (
                        <span className="bg-amber-500/15 text-amber-300 border border-amber-500/25 rounded px-1.5 py-0.5">
                          ⚠️ {p.missing_or_uncertain_evidence.length} Uncertain Evidence Gap(s)
                        </span>
                      )}
                      <span className="ml-auto text-zinc-500 text-[10px]">
                        {isExpanded ? '▲ Hide breakdown' : '▼ View hop rationale'}
                      </span>
                    </div>
                  </div>

                  {/* Expanded Step Details */}
                  {isExpanded && (
                    <div className="px-3 pb-3 pt-1 border-t border-white/5 space-y-2 text-xs bg-black/20">
                      <div className="text-[11px] text-zinc-300">
                        <strong className="text-zinc-400">Why feasible:</strong> {p.why_possible}
                      </div>

                      <div className="space-y-1.5 mt-2">
                        <div className="text-[10px] uppercase font-semibold text-zinc-400 tracking-wider">
                          Hop-by-Hop Breakdown
                        </div>
                        {p.step_details?.map((step, idx) => (
                          <div key={idx} className="bg-white/[0.03] border border-white/5 rounded p-2 text-[11px]">
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-zinc-200">
                                Hop {idx + 1}: {names[step.from_device] || step.from_device} → {names[step.to_device] || step.to_device}
                              </span>
                              <span className={`text-[10px] px-1.5 py-0.2 rounded ${
                                step.evidence_status === 'confirmed' ? 'text-emerald-300 bg-emerald-500/10' :
                                step.evidence_status === 'probable' ? 'text-sky-300 bg-sky-500/10' :
                                'text-amber-300 bg-amber-500/10'
                              }`}>
                                {step.evidence_status}
                              </span>
                            </div>
                            <div className="text-zinc-300 mt-1">
                              {step.rationale}
                            </div>
                            <div className="text-zinc-500 text-[10px] mt-1 flex gap-2 font-mono">
                              <span>Protocol: {step.via_protocol}{step.via_port ? `:${step.via_port}` : ''}</span>
                              <span>Policy: {step.policy_status}</span>
                              <span>Zeek Observed: {step.observed ? 'Yes' : 'No'}</span>
                            </div>
                          </div>
                        ))}
                      </div>

                      {p.missing_or_uncertain_evidence?.length > 0 && (
                        <div className="mt-2 bg-amber-950/20 border border-amber-500/20 rounded p-2 text-[11px] text-amber-200/90">
                          <div className="font-semibold text-[10px] uppercase tracking-wider text-amber-300 mb-1">
                            Missing or Uncertain Evidence
                          </div>
                          <ul className="list-disc pl-4 space-y-0.5 text-[10px]">
                            {p.missing_or_uncertain_evidence.map((gap, gIdx) => (
                              <li key={gIdx}>{gap}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </Section>

      {/* EXPOSED NETWORK SERVICES SECTION */}
      <Section title={`Exposed Services (${reachableServicesList.length})`}>
        {reachableServicesList.length === 0 ? (
          <Empty>No services reachable from the compromised device.</Empty>
        ) : (
          <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
            {reachableServicesList.map((s, idx) => (
              <div
                key={idx}
                onClick={() => setFocus({ key: `node:${s.target_device}`, node: s.target_device, path: s.path })}
                className="bg-white/[0.03] border border-white/5 rounded p-2 text-xs hover:bg-white/[0.06] cursor-pointer"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <span className="font-semibold text-zinc-200">{s.target_device_name}</span>
                    <span className="text-zinc-400 ml-2 font-mono">{s.service_name}:{s.port}/{s.protocol}</span>
                  </div>
                  <span className="text-[10px] text-zinc-400 font-mono">{s.hops} hop(s)</span>
                </div>
                {s.vulnerabilities?.length > 0 && (
                  <div className="mt-1 flex flex-wrap gap-1">
                    {s.vulnerabilities.map((v) => (
                      <span
                        key={v.id}
                        className={`text-[9px] px-1 py-0.2 rounded font-mono ${
                          v.exploit_available
                            ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                            : 'bg-orange-500/20 text-orange-300 border border-orange-500/30'
                        }`}
                      >
                        {v.id} {v.exploit_available ? '⚡' : ''}
                      </span>
                    ))}
                  </div>
                )}
                <div className="text-[10px] text-zinc-500 mt-1">{s.status_explanation}</div>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* REACHABLE DEVICES SUMMARY */}
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

      {/* CRITICAL ASSETS SUMMARY */}
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

      {/* RISK RANKING */}
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
