import { useState } from 'react'
import {
  Section,
  Empty,
  PathText,
  CritBadge,
  EvidenceBadge,
  PolicyBadge,
  ObservedBadge,
  Table,
  Row,
  Icon,
} from './ui'

export default function ResultsPanel({
  analysis,
  risk,
  critical,
  services: _services,
  attackPaths,
  names,
  focus,
  setFocus,
}) {
  const [expandedPathId, setExpandedPathId] = useState(null)
  const [showOnlyExploitable, setShowOnlyExploitable] = useState(false)

  if (!analysis) return null

  const paths = attackPaths?.attack_paths || []
  const filteredPaths = showOnlyExploitable
    ? paths.filter((p) => p.vulnerabilities_exploitable_count > 0)
    : paths

  const criticalAssetsList = critical?.critical_assets || []
  const riskResults = risk?.results || []

  return (
    <div className="space-y-1">
      {/* ---------------------------------------------------------------------
          1. CRITICAL ASSETS AT RISK
      --------------------------------------------------------------------- */}
      <Section
        title="Critical Assets at Risk"
        count={critical?.count ?? 0}
        collapsible
        defaultOpen={true}
      >
        {!critical || critical.count === 0 ? (
          <Empty>No high-value assets (criticality ≥ {critical?.threshold ?? 4}) are reachable from patient zero.</Empty>
        ) : (
          <div className="space-y-1.5">
            {criticalAssetsList.map((a) => {
              const isSelected = focus?.key === `asset:${a.device_id}`
              return (
                <div
                  key={a.device_id}
                  onClick={() => setFocus({ key: `asset:${a.device_id}`, path: a.path, node: a.device_id })}
                  className={`row border border-line ${isSelected ? 'row-active' : ''}`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-fg text-xs">{a.name}</span>
                      <CritBadge value={a.criticality} />
                    </div>
                    <span className="mono text-fg-subtle text-[11px]">
                      {a.hops} hop{a.hops > 1 ? 's' : ''}
                    </span>
                  </div>
                  <div className="mt-1">
                    <PathText path={a.path} names={names} />
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Section>

      {/* ---------------------------------------------------------------------
          2. DISCOVERED POTENTIAL ATTACK PATHS
      --------------------------------------------------------------------- */}
      <Section
        title="Potential Attack Paths"
        count={paths.length}
        collapsible
        defaultOpen={true}
        right={
          paths.length > 0 ? (
            <label className="flex items-center gap-1.5 text-[11px] text-fg-subtle cursor-pointer hover:text-fg">
              <input
                type="checkbox"
                checked={showOnlyExploitable}
                onChange={(e) => setShowOnlyExploitable(e.target.checked)}
                className="accent-danger"
              />
              <span>Known Exploits Only</span>
            </label>
          ) : null
        }
      >
        {paths.length === 0 ? (
          <Empty>No multi-hop traversal paths found to critical targets.</Empty>
        ) : (
          <div className="space-y-2">
            {filteredPaths.map((p) => {
              const isSelected = focus?.key === `path:${p.path_id}`
              const isExpanded = expandedPathId === p.path_id
              const feasibilityTone =
                p.feasibility_level === 'high'
                  ? 'badge-danger'
                  : p.feasibility_level === 'medium'
                  ? 'badge-warn'
                  : 'badge-neutral'

              return (
                <div
                  key={p.path_id}
                  className={`rounded-md border transition-colors ${
                    isSelected ? 'border-accent bg-accent/5 ring-1 ring-accent/30' : 'border-line bg-s2/40'
                  }`}
                >
                  {/* Path Card Summary Header */}
                  <div
                    onClick={() => {
                      setFocus({ key: `path:${p.path_id}`, path: p.path })
                      setExpandedPathId(isExpanded ? null : p.path_id)
                    }}
                    className="p-2.5 cursor-pointer hover:bg-s3/50 rounded-t-md"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`badge ${feasibilityTone}`}>
                          {p.feasibility_level} · {p.feasibility_score}%
                        </span>
                        <span className="font-semibold text-xs text-fg">{p.target_device_name}</span>
                      </div>
                      <div className="flex items-center gap-1.5 mono text-[11px] text-fg-subtle">
                        <CritBadge value={p.target_criticality} />
                        <span>· {p.hops_count}h</span>
                      </div>
                    </div>

                    <div className="mt-1.5">
                      <PathText path={p.path} names={names} />
                    </div>

                    {/* Threat & Evidence Highlights */}
                    <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[10px]">
                      {p.vulnerabilities_exploitable_count > 0 && (
                        <span className="badge badge-danger">
                          ⚡ {p.vulnerabilities_exploitable_count} Known Exploit(s)
                        </span>
                      )}
                      {p.missing_or_uncertain_evidence?.length > 0 && (
                        <span className="badge badge-warn">
                          ⚠ {p.missing_or_uncertain_evidence.length} Uncertain Evidence Gap(s)
                        </span>
                      )}
                      <span className="ml-auto text-fg-subtle hover:text-fg text-[11px] flex items-center gap-1">
                        {isExpanded ? 'Hide hops' : 'Hop breakdown'}
                        <Icon name={isExpanded ? 'chevronDown' : 'chevronRight'} size={11} />
                      </span>
                    </div>
                  </div>

                  {/* Expanded Hop Breakdown */}
                  {isExpanded && (
                    <div className="border-t border-line bg-s1/60 p-3 space-y-2.5 text-xs">
                      <div>
                        <span className="text-fg-subtle font-medium">Why Feasible: </span>
                        <span className="text-fg-muted">{p.why_possible}</span>
                      </div>

                      <div className="space-y-1.5 pt-1">
                        <div className="eyebrow text-fg-subtle">Step-by-Step Traversal</div>
                        {p.step_details?.map((step, idx) => (
                          <div
                            key={idx}
                            className="rounded border border-line bg-s2/60 p-2 space-y-1 text-[11px]"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-fg">
                                Step {idx + 1}: {names[step.from_device] || step.from_device} →{' '}
                                {names[step.to_device] || step.to_device}
                              </span>
                              <EvidenceBadge status={step.evidence_status} />
                            </div>

                            <p className="text-fg-muted leading-relaxed">{step.rationale}</p>

                            <div className="flex flex-wrap items-center gap-2 pt-0.5 mono text-[10px] text-fg-subtle">
                              <span>
                                Protocol: {step.via_protocol}
                                {step.via_port ? `:${step.via_port}` : ''}
                              </span>
                              <div className="flex items-center gap-1.5">
                                <span className="text-fg-subtle">Policy:</span>
                                <PolicyBadge status={step.policy_status} />
                              </div>
                              <span>·</span>
                              <div className="flex items-center gap-1.5">
                                <span className="text-fg-subtle">Traffic:</span>
                                <ObservedBadge observed={step.observed} />
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>

                      {p.missing_or_uncertain_evidence?.length > 0 && (
                        <div className="rounded border border-warn/30 bg-warn/5 p-2 text-[11px] text-warn space-y-1">
                          <div className="font-semibold uppercase tracking-wider text-[10px]">
                            Missing or Uncertain Evidence
                          </div>
                          <ul className="list-disc pl-4 space-y-0.5 text-fg-muted text-[10px]">
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

      {/* ---------------------------------------------------------------------
          3. RISK RANKING
      --------------------------------------------------------------------- */}
      <Section
        title="Asset Risk Ranking"
        count={riskResults.length}
        collapsible
        defaultOpen={false}
      >
        {riskResults.length === 0 ? (
          <Empty>No exposed devices to rank.</Empty>
        ) : (
          <div className="space-y-2">
            <Table head={['Asset Name', 'Crit.', 'Hops', 'Risk Score']}>
              {riskResults.map((r) => {
                const key = `risk:${r.device_id}`
                return (
                  <Row
                    key={r.device_id}
                    active={focus?.key === key}
                    onClick={() => setFocus({ key, path: r.path, node: r.device_id })}
                    cells={[
                      r.name,
                      <CritBadge key="c" value={r.criticality} />,
                      `${r.hops}h`,
                      <span key="s" className="font-semibold text-fg">
                        {r.risk_score.toFixed(1)}
                      </span>,
                    ]}
                  />
                )
              })}
            </Table>
            <p className="text-[10px] text-fg-subtle leading-relaxed">
              Deterministic heuristic: (Criticality / 5) × 100 ÷ Hop distance. Represents relative exposure priority, not a calibrated exploit probability.
            </p>
          </div>
        )}
      </Section>
    </div>
  )
}
