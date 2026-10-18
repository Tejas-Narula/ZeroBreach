export function Section({ title, children, right }) {
  return (
    <section className="border-b border-white/5 px-4 py-3">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">{title}</h2>
        {right}
      </div>
      {children}
    </section>
  )
}

export function Empty({ children }) {
  return <p className="text-xs text-zinc-500">{children}</p>
}

export function Table({ head, children }) {
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-left text-zinc-500">
          {head.map((h, i) => (
            <th key={h} className={`pb-1 font-medium ${i > 0 ? 'text-right' : ''}`}>{h}</th>
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
      className={`cursor-pointer border-t border-white/5 ${active ? 'bg-sky-500/10' : 'hover:bg-white/[0.03]'}`}
    >
      {cells.map((c, i) => (
        <td key={i} className={`py-1.5 ${i > 0 ? 'text-right font-mono' : ''}`}>{c}</td>
      ))}
    </tr>
  )
}

export function PathText({ path, names }) {
  return (
    <span className="font-mono text-[11px] text-zinc-400">
      {path.map((id) => names[id] || id).join(' → ')}
    </span>
  )
}
