import React from 'react'

export const NODE_TEMPLATES = [
  {
    type: 'laptop',
    name: 'Laptop',
    icon: '/computer.png',
    defaultCriticality: 1,
    zone: 'employee',
    description: 'Endpoint workstation / user device',
  },
  {
    type: 'server',
    name: 'Server',
    icon: '/server.png',
    defaultCriticality: 3,
    zone: 'internal',
    description: 'Application or API host server',
  },
  {
    type: 'database',
    name: 'Database',
    icon: '/server.png',
    defaultCriticality: 5,
    zone: 'restricted',
    description: 'High-value customer or transactional data',
  },
  {
    type: 'router',
    name: 'Router',
    icon: '/wifi-router.png',
    defaultCriticality: 3,
    zone: 'perimeter',
    description: 'Network gateway & routing device',
  },
  {
    type: 'firewall',
    name: 'Firewall',
    icon: '/hub.png',
    defaultCriticality: 4,
    zone: 'perimeter',
    description: 'Security boundary inspection & filter',
  },
  {
    type: 'hub',
    name: 'Switch / Hub',
    icon: '/hub.png',
    defaultCriticality: 2,
    zone: 'internal',
    description: 'Network switch or distribution hub',
  },
]

// Global fallback transfer for cross-browser drop compatibility
export let currentDraggedTemplate = null

export default function NodePalette() {
  const onDragStart = (e, template) => {
    currentDraggedTemplate = template
    const jsonStr = JSON.stringify(template)
    try {
      e.dataTransfer.setData('text/plain', jsonStr)
      e.dataTransfer.setData('application/json', jsonStr)
    } catch {
      // ignore
    }
    e.dataTransfer.effectAllowed = 'copy'
  }

  const onDragEnd = () => {
    currentDraggedTemplate = null
  }

  return (
    <aside className="w-[180px] shrink-0 border-r border-white/5 bg-[#0e1115] flex flex-col select-none">
      <div className="border-b border-white/5 px-3 py-2.5">
        <h2 className="text-[11px] font-semibold uppercase tracking-wider text-zinc-400">
          Device Palette
        </h2>
        <p className="text-[10px] text-zinc-500 mt-0.5">Drag & drop onto canvas</p>
      </div>

      <div className="flex-1 overflow-y-auto p-2.5 space-y-2">
        {NODE_TEMPLATES.map((tmpl) => (
          <div
            key={tmpl.type}
            draggable
            onDragStart={(e) => onDragStart(e, tmpl)}
            onDragEnd={onDragEnd}
            className="group flex items-center gap-2.5 rounded-lg border border-white/5 bg-white/[0.02] p-2 hover:bg-white/[0.06] hover:border-sky-500/40 cursor-grab active:cursor-grabbing transition"
          >
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded bg-black/40 p-1 border border-white/5 group-hover:border-sky-500/30">
              <img
                src={tmpl.icon}
                alt={tmpl.name}
                className="h-7 w-7 object-contain pointer-events-none drop-shadow"
              />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-zinc-200 truncate group-hover:text-white">
                  {tmpl.name}
                </span>
                <span className="font-mono text-[9px] text-zinc-500">
                  C{tmpl.defaultCriticality}
                </span>
              </div>
              <p className="text-[10px] text-zinc-500 truncate capitalize">{tmpl.zone}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="p-3 border-t border-white/5 bg-white/[0.01] text-[10px] text-zinc-500">
        <span className="text-zinc-400 font-medium">Tip:</span> Drag any device to the canvas to place it at that location.
      </div>
    </aside>
  )
}
