import React from 'react'

export default function AnalysisStatsSidebar({ results, impact, names, compromisedId }) {
  if (!results) {
    return (
      <aside className="w-[230px] shrink-0 border-r border-white/5 bg-[#0e1115] flex flex-col select-none p-4 text-xs text-zinc-500">
        <div className="border-b border-white/5 pb-2.5 mb-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-wider text-zinc-400">
            Attack Impact Summary
          </h2>
          <p className="text-[10px] text-zinc-500 mt-0.5">Overview & Blast Radius</p>
        </div>
        <p>No attack analysis run yet. Select a compromised device and click "Analyze" to see stats.</p>
      </aside>
    )
  }

  const { analysis, risk, critical } = results
  const reachableCount = analysis?.reachable_count || 0
  const exposedCriticalCount = critical?.count || 0
  const highestRiskDevice = risk?.results?.[0]
  const compromisedName = names[compromisedId] || compromisedId

  // Calculate highest risk score or average
  const maxRisk = highestRiskDevice ? highestRiskDevice.risk_score : 0
  const totalRisk = risk?.results?.reduce((sum, r) => sum + r.risk_score, 0) || 0

  return (
    <aside className="w-[230px] shrink-0 border-r border-white/5 bg-[#0e1115] flex flex-col select-none overflow-y-auto">
      <div className="border-b border-white/5 px-3.5 py-3 bg-white/[0.01]">
        <h2 className="text-[11px] font-semibold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full bg-red-500 animate-pulse" />
          Attack Blast Radius
        </h2>
        <p className="text-[10px] text-zinc-400 mt-1 truncate">
          Patient Zero: <strong className="text-zinc-200">{compromisedName}</strong>
        </p>
      </div>

      <div className="p-3.5 space-y-3 flex-1">
        {/* Metric Card 1: Reachable devices */}
        <div className="rounded-lg border border-white/5 bg-white/[0.02] p-2.5">
          <div className="text-[10px] uppercase tracking-wider text-zinc-500">Exposed Devices</div>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className="text-xl font-bold font-mono text-zinc-100">{reachableCount}</span>
            <span className="text-[10px] text-zinc-500">reachable nodes</span>
          </div>
        </div>

        {/* Metric Card 2: Critical Assets Exposed */}
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.04] p-2.5">
          <div className="text-[10px] uppercase tracking-wider text-amber-400/90 font-medium">Critical Assets At Risk</div>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className="text-xl font-bold font-mono text-amber-300">{exposedCriticalCount}</span>
            <span className="text-[10px] text-amber-400/70">C{critical?.threshold || 4}+ assets</span>
          </div>
          {exposedCriticalCount > 0 && (
            <div className="mt-2 text-[10px] text-zinc-400 space-y-0.5 border-t border-amber-500/10 pt-1.5">
              {critical.critical_assets.map((a) => (
                <div key={a.device_id} className="flex justify-between items-center">
                  <span className="truncate max-w-[120px]">{a.name}</span>
                  <span className="font-mono text-amber-300/80">{a.hops} hop{a.hops > 1 ? 's' : ''}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Metric Card 3: Attack Paths & Feasibility */}
        {results?.attackPaths && (
          <div className="rounded-lg border border-red-500/20 bg-red-500/[0.04] p-2.5">
            <div className="text-[10px] uppercase tracking-wider text-red-400 font-medium">Attack Paths Discovered</div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span className="text-xl font-bold font-mono text-red-300">
                {results.attackPaths.total_attack_paths}
              </span>
              <span className="text-[10px] text-zinc-400">paths to critical</span>
            </div>
            {results.attackPaths.attack_paths?.length > 0 && (
              <div className="mt-1.5 text-[10px] text-zinc-400 border-t border-red-500/10 pt-1 flex justify-between">
                <span>Top Feasibility:</span>
                <span className="font-mono text-red-300 font-semibold">
                  {results.attackPaths.attack_paths[0].feasibility_level} ({results.attackPaths.attack_paths[0].feasibility_score}%)
                </span>
              </div>
            )}
          </div>
        )}

        {/* Metric Card 4: Exposed Services & Vulns */}
        {results?.services && (
          <div className="rounded-lg border border-white/5 bg-white/[0.02] p-2.5">
            <div className="text-[10px] uppercase tracking-wider text-zinc-500">Service Exposure</div>
            <div className="mt-1 flex items-baseline justify-between">
              <div>
                <span className="text-xl font-bold font-mono text-zinc-100">{results.services.total_services_exposed}</span>
                <span className="text-[10px] text-zinc-500 ml-1">services</span>
              </div>
              <div>
                <span className="text-sm font-bold font-mono text-red-400">{results.services.services_with_vulnerabilities}</span>
                <span className="text-[10px] text-zinc-500 ml-1">vulnerable</span>
              </div>
            </div>
          </div>
        )}

        {/* Metric Card 5: Aggregate Risk */}
        <div className="rounded-lg border border-white/5 bg-white/[0.02] p-2.5">
          <div className="text-[10px] uppercase tracking-wider text-zinc-500">Aggregate Risk Index</div>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className="text-xl font-bold font-mono text-rose-400">{totalRisk.toFixed(1)}</span>
            <span className="text-[10px] text-zinc-500">total score</span>
          </div>
          {highestRiskDevice && (
            <div className="mt-1.5 text-[10px] text-zinc-400 border-t border-white/5 pt-1">
              Top target: <span className="text-zinc-200">{highestRiskDevice.name}</span> ({highestRiskDevice.risk_score})
            </div>
          )}
        </div>

        {/* Containment Impact Summary (if simulated) */}
        {impact && (
          <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.04] p-2.5">
            <div className="text-[10px] uppercase tracking-wider text-emerald-400 font-medium">
              Containment Potential
            </div>
            <div className="mt-1.5 space-y-1 text-[11px]">
              <div className="flex justify-between">
                <span className="text-zinc-400">Risk Reduction:</span>
                <span className="font-mono font-bold text-emerald-300">
                  {impact.percentage_risk_reduction}%
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-400">Assets Saved:</span>
                <span className="font-mono text-emerald-300">
                  {impact.protected_critical_assets?.length || 0}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-400">Disruption Cost:</span>
                <span className="font-mono text-zinc-300">
                  {impact.total_disruption_cost}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="p-3 border-t border-white/5 bg-white/[0.01] text-[10px] text-zinc-500">
        Review full paths, ranking details, and containment controls in the right panel.
      </div>
    </aside>
  )
}
