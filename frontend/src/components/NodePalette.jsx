import { useState } from 'react'
import { Icon, IconButton } from './ui'
import { setDraggedTemplate } from '../utils/graphStorage'

const NODE_TEMPLATES = [
  { type: 'endpoint', name: 'Endpoint', icon: '/computer.svg', defaultCriticality: 1, zone: 'employee', group: 'Hosts', description: 'Workstations, laptops, desktops' },
  { type: 'server', name: 'Server', icon: '/server.svg', defaultCriticality: 3, zone: 'internal', group: 'Hosts', description: 'Application, web, and service servers' },
  { type: 'database', name: 'Database', icon: '/database.svg', defaultCriticality: 4, zone: 'restricted', group: 'Hosts', description: 'Relational & distributed data stores' },
  { type: 'iot_device', name: 'IoT Device', icon: '/iot.svg', defaultCriticality: 2, zone: 'internal', group: 'Hosts', description: 'Cameras, smart sensors, and controllers' },
  { type: 'network_device', name: 'Network Device', icon: '/router.svg', defaultCriticality: 3, zone: 'internal', group: 'Network', description: 'Core routers, switches, and relays' },
  { type: 'firewall', name: 'Firewall', icon: '/firewall.svg', defaultCriticality: 4, zone: 'perimeter', group: 'Network', description: 'Security gateways and packet filters' },
  { type: 'wireless_access_point', name: 'Wireless AP', icon: '/wap.svg', defaultCriticality: 2, zone: 'employee', group: 'Network', description: 'Wi-Fi access points & controllers' },
  { type: 'security_system', name: 'Security System', icon: '/security.svg', defaultCriticality: 4, zone: 'restricted', group: 'Network', description: 'IDS/IPS sensors, SIEM, & monitoring' },
  { type: 'cloud_infrastructure', name: 'Cloud Infra', icon: '/cloud.svg', defaultCriticality: 3, zone: 'dmz', group: 'Other', description: 'Cloud compute, VPC gateways, & storage' },
  { type: 'external', name: 'External', icon: '/external.svg', defaultCriticality: 1, zone: 'external', group: 'Other', description: 'Internet endpoints & third-party services' },
  { type: 'unknown', name: 'Unknown', icon: '/unknown.svg', defaultCriticality: 2, zone: 'internal', group: 'Other', description: 'Unclassified network host (provisional)' },
]

const GROUPS = ['Hosts', 'Network', 'Other']

export default function NodePalette({ collapsed, onToggle }) {
  const [query, setQuery] = useState('')

  const onDragStart = (e, template) => {
    setDraggedTemplate(template)
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
    setDraggedTemplate(null)
  }

  if (collapsed) {
    return (
      <aside className="flex w-11 shrink-0 flex-col items-center gap-1 border-r border-line bg-s1 py-2">
        <IconButton icon="chevronRight" label="Expand device palette" onClick={onToggle} />
        <div className="my-1 h-px w-6 bg-line" />
        {NODE_TEMPLATES.map((t) => (
          <div
            key={t.type}
            draggable
            onDragStart={(e) => onDragStart(e, t)}
            onDragEnd={onDragEnd}
            title={`Drag to add: ${t.name}`}
            className="flex h-8 w-8 cursor-grab items-center justify-center rounded-md hover:bg-s3 active:cursor-grabbing"
          >
            <img src={t.icon} alt={t.name} className="pointer-events-none h-5 w-5 object-contain" />
          </div>
        ))}
      </aside>
    )
  }

  const q = query.trim().toLowerCase()
  const filtered = NODE_TEMPLATES.filter(
    (t) => !q || t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q),
  )

  return (
    <aside className="flex w-52 shrink-0 select-none flex-col border-r border-line bg-s1">
      <div className="flex h-10 items-center justify-between border-b border-line pl-3 pr-1.5">
        <span className="eyebrow">Devices</span>
        <IconButton icon="chevronLeft" label="Collapse device palette" onClick={onToggle} />
      </div>

      <div className="p-2">
        <div className="relative">
          <Icon name="search" size={12} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-fg-subtle" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter devices"
            aria-label="Filter device types"
            className="input pl-6"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-2 pb-2">
        {GROUPS.map((g) => {
          const items = filtered.filter((t) => t.group === g)
          if (items.length === 0) return null
          return (
            <div key={g} className="mb-2">
              <div className="px-1 pb-1 pt-1.5 text-[10px] font-semibold uppercase tracking-wider text-fg-subtle">{g}</div>
              {items.map((t) => (
                <div
                  key={t.type}
                  draggable
                  onDragStart={(e) => onDragStart(e, t)}
                  onDragEnd={onDragEnd}
                  title={`${t.description} — drag onto the canvas`}
                  className="group flex h-8 cursor-grab items-center gap-2 rounded-md px-1.5 hover:bg-s3 active:cursor-grabbing"
                >
                  <img src={t.icon} alt="" className="pointer-events-none h-5 w-5 object-contain" />
                  <span className="flex-1 truncate text-xs text-fg">{t.name}</span>
                  <span className="mono text-fg-subtle opacity-0 group-hover:opacity-100">C{t.defaultCriticality}</span>
                </div>
              ))}
            </div>
          )
        })}
        {filtered.length === 0 && <p className="px-1 text-xs text-fg-subtle">No matching device types.</p>}
      </div>

      <div className="border-t border-line px-3 py-2 text-[11px] text-fg-subtle">Drag onto the canvas to add.</div>
    </aside>
  )
}
