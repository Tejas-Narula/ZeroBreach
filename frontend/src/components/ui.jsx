import { useState } from 'react'

/* ---------------------------------------------------------------------------
   Icons — small inline SVG set (stroke-based, 16px) so no icon library is needed
--------------------------------------------------------------------------- */
const ICON_PATHS = {
  plus: 'M12 5v14M5 12h14',
  x: 'M18 6 6 18M6 6l12 12',
  edit: 'M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z',
  trash: 'M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6',
  link: 'M10 13a5 5 0 0 0 7.07 0l3-3a5 5 0 0 0-7.07-7.07l-1 1M14 11a5 5 0 0 0-7.07 0l-3 3a5 5 0 0 0 7.07 7.07l1-1',
  upload: 'M12 16V4M7 9l5-5 5 5M4 20h16',
  zoomIn: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM21 21l-4.3-4.3M11 8v6M8 11h6',
  zoomOut: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM21 21l-4.3-4.3M8 11h6',
  fit: 'M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5',
  target: 'M12 3v3M12 18v3M3 12h3M18 12h3M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z',
  chevronLeft: 'm15 18-6-6 6-6',
  chevronRight: 'm9 18 6-6-6-6',
  chevronDown: 'm6 9 6 6 6-6',
  alert: 'M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z',
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z',
  play: 'M6 4l14 8-14 8Z',
  info: 'M12 16v-4M12 8h.01M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM21 21l-4.3-4.3',
  graph: 'M6 6m-2 0a2 2 0 1 0 4 0 2 2 0 1 0-4 0M18 6m-2 0a2 2 0 1 0 4 0 2 2 0 1 0-4 0M12 18m-2 0a2 2 0 1 0 4 0 2 2 0 1 0-4 0M8 6h8M7 8l4 8M17 8l-4 8',
  reset: 'M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5',
}

export function Icon({ name, size = 14, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`shrink-0 ${className}`}
      aria-hidden="true"
    >
      <path d={ICON_PATHS[name]} />
    </svg>
  )
}

export function IconButton({ icon, label, onClick, disabled, active, className = '' }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={label}
      aria-label={label}
      className={`btn btn-icon ${active ? 'bg-accent/15 text-accent' : 'btn-ghost'} ${className}`}
    >
      <Icon name={icon} />
    </button>
  )
}

/* ---------------------------------------------------------------------------
   Layout primitives
--------------------------------------------------------------------------- */
export function Section({ title, count, children, right, collapsible = false, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen)
  const header = (
    <>
      <span className="eyebrow">{title}</span>
      {count !== undefined && <span className="badge badge-neutral">{count}</span>}
    </>
  )
  return (
    <section className="border-b border-line px-4 py-3">
      <div className="mb-2 flex min-h-6 items-center justify-between gap-2">
        {collapsible ? (
          <button
            type="button"
            onClick={() => setOpen(!open)}
            className="flex items-center gap-1.5"
            aria-expanded={open}
          >
            <Icon name={open ? 'chevronDown' : 'chevronRight'} size={12} className="text-fg-subtle" />
            {header}
          </button>
        ) : (
          <div className="flex items-center gap-1.5">{header}</div>
        )}
        {right}
      </div>
      {(!collapsible || open) && children}
    </section>
  )
}

export function Empty({ children }) {
  return <p className="py-1 text-xs text-fg-subtle">{children}</p>
}

export function KV({ label, children }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1 text-xs">
      <span className="shrink-0 text-fg-subtle">{label}</span>
      <span className="min-w-0 text-right text-fg [overflow-wrap:anywhere]">{children ?? <Unknown />}</span>
    </div>
  )
}

/** Explicit marker for missing data — never invent values */
export function Unknown({ children = 'Not recorded' }) {
  return <span className="italic text-fg-subtle">{children}</span>
}

export function Tabs({ tabs, value, onChange }) {
  return (
    <div role="tablist" className="flex gap-1 border-b border-line px-3">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          type="button"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={`-mb-px flex h-8 items-center gap-1.5 border-b-2 px-2 text-xs font-medium transition-colors ${
            value === t.id ? 'border-accent text-fg' : 'border-transparent text-fg-subtle hover:text-fg'
          }`}
        >
          {t.label}
          {t.count !== undefined && t.count > 0 && <span className="badge badge-neutral">{t.count}</span>}
        </button>
      ))}
    </div>
  )
}

export function Field({ label, error, children, hint }) {
  return (
    <label className="block">
      <span className="label">{label}</span>
      {children}
      {hint && !error && <span className="mt-1 block text-[11px] text-fg-subtle">{hint}</span>}
      {error && <span className="field-error block">{error}</span>}
    </label>
  )
}

export function Metric({ label, value, tone = 'neutral', hint }) {
  const toneClass = {
    neutral: 'text-fg',
    danger: 'text-danger',
    crit: 'text-crit',
    warn: 'text-warn',
    ok: 'text-ok',
  }[tone]
  return (
    <div className="min-w-0 rounded-md border border-line bg-s1 px-3 py-2" title={hint}>
      <div className="truncate text-[11px] text-fg-subtle">{label}</div>
      <div className={`mt-0.5 font-mono text-lg font-semibold leading-tight ${toneClass}`}>{value}</div>
    </div>
  )
}

/* ---------------------------------------------------------------------------
   Semantic badges — always text + color (never color alone)
--------------------------------------------------------------------------- */
export function CritBadge({ value }) {
  const cls = value >= 5 ? 'badge-danger' : value >= 4 ? 'badge-crit' : 'badge-neutral'
  return (
    <span className={`badge ${cls}`} title={`Criticality ${value} of 5`}>
      C{value}
    </span>
  )
}

export function PolicyBadge({ status, allowed }) {
  const s = status || (allowed ? 'allowed' : 'denied')
  const cls = { allowed: 'badge-ok', denied: 'badge-danger', unknown: 'badge-unknown' }[s] || 'badge-neutral'
  const title = {
    allowed: 'Policy permits this flow — traversable in analysis',
    denied: 'Policy blocks this flow — not traversable',
    unknown: 'Policy not confirmed — treated as uncertain',
  }[s]
  return (
    <span className={`badge ${cls}`} title={title}>
      {s}
    </span>
  )
}

export function ObservedBadge({ observed }) {
  return observed ? (
    <span className="badge badge-accent" title="Seen in traffic logs. Observed ≠ authorized.">observed</span>
  ) : (
    <span className="badge badge-neutral" title="No traffic observation recorded">not observed</span>
  )
}

export function SeverityBadge({ severity, cvss }) {
  const cls =
    { critical: 'badge-danger', high: 'badge-danger', medium: 'badge-warn', low: 'badge-neutral', info: 'badge-neutral' }[
      severity
    ] || 'badge-neutral'
  return (
    <span className={`badge ${cls}`}>
      {severity || 'unrated'}
      {cvss != null && <span className="font-mono opacity-80">{cvss}</span>}
    </span>
  )
}

export function EvidenceBadge({ status }) {
  const map = {
    confirmed: ['badge-ok', 'Policy allowed and traffic observed'],
    probable: ['badge-accent', 'Policy allows it, but no traffic observed'],
    speculative_policy_unknown: ['badge-unknown', 'Policy status unknown — assumption'],
    weak_evidence: ['badge-warn', 'Weak supporting evidence'],
  }
  const [cls, title] = map[status] || ['badge-neutral', status]
  const label = status === 'speculative_policy_unknown' ? 'policy unknown' : status?.replace(/_/g, ' ')
  return (
    <span className={`badge ${cls}`} title={title}>
      {label}
    </span>
  )
}

export function PathText({ path, names }) {
  return (
    <span className="font-mono text-[11px] text-fg-muted">
      {path.map((id, i) => (
        <span key={`${id}-${i}`}>
          {i > 0 && <span className="px-1 text-fg-subtle">→</span>}
          {names[id] || id}
        </span>
      ))}
    </span>
  )
}

/* Legacy table helpers kept for compatibility */
export function Table({ head, children }) {
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-left text-fg-subtle">
          {head.map((h, i) => (
            <th key={h} className={`pb-1.5 font-medium ${i > 0 ? 'text-right' : ''}`}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>{children}</tbody>
    </table>
  )
}

export function Row({ active, onClick, cells }) {
  return (
    <tr
      onClick={onClick}
      className={`cursor-pointer border-t border-line ${active ? 'bg-accent/10' : 'hover:bg-s3'}`}
    >
      {cells.map((c, i) => (
        <td key={i} className={`py-1.5 ${i > 0 ? 'text-right font-mono' : ''}`}>{c}</td>
      ))}
    </tr>
  )
}
