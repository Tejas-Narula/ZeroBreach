import React from 'react'

export const NODE_TEMPLATES = [
  {
    type: 'endpoint',
    name: 'Endpoint',
    icon: '/computer.png',
    defaultCriticality: 1,
    zone: 'employee',
    description: 'Workstations, laptops, desktops',
  },
  {
    type: 'server',
    name: 'Server',
    icon: '/server.png',
    defaultCriticality: 3,
    zone: 'internal',
    description: 'Application, web, and service servers',
  },
  {
    type: 'database',
    name: 'Database',
    icon: '/database.svg',
    defaultCriticality: 4,
    zone: 'restricted',
    description: 'Relational & distributed data stores',
  },
  {
    type: 'network_device',
    name: 'Network Device',
    icon: '/wifi-router.png',
    defaultCriticality: 3,
    zone: 'internal',
    description: 'Core routers, switches, and relays',
  },
  {
    type: 'firewall',
    name: 'Firewall',
    icon: '/firewall.svg',
    defaultCriticality: 4,
    zone: 'perimeter',
    description: 'Security gateways and packet filters',
  },
  {
    type: 'wireless_access_point',
    name: 'Wireless AP',
    icon: '/wap.svg',
    defaultCriticality: 2,
    zone: 'employee',
    description: 'Wi-Fi access points & controllers',
  },
  {
    type: 'cloud_infrastructure',
    name: 'Cloud Infra',
    icon: '/cloud.svg',
    defaultCriticality: 3,
    zone: 'dmz',
    description: 'Cloud compute, VPC gateways, & storage',
  },
  {
    type: 'security_system',
    name: 'Security System',
    icon: '/security.svg',
    defaultCriticality: 4,
    zone: 'restricted',
    description: 'IDS/IPS sensors, SIEM, & monitoring',
  },
  {
    type: 'iot_device',
    name: 'IoT Device',
    icon: '/iot.svg',
    defaultCriticality: 2,
    zone: 'internal',
    description: 'Cameras, smart sensors, and controllers',
  },
  {
    type: 'external',
    name: 'External',
    icon: '/external.svg',
    defaultCriticality: 1,
    zone: 'external',
    description: 'Internet endpoints & third-party services',
  },
  {
    type: 'unknown',
    name: 'Unknown Device',
    icon: '/unknown.svg',
    defaultCriticality: 2,
    zone: 'internal',
    description: 'Unclassified network host (provisional)',
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
