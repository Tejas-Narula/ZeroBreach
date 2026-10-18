import { useState, useEffect } from 'react'
import { Section } from './ui'

const DEVICE_TYPES = ['laptop', 'workstation', 'server', 'database', 'firewall', 'router']
const PROTOCOLS = ['HTTPS', 'HTTP', 'SSH', 'SQL', 'TCP', 'RDP', 'DNS']
const ZONES = ['employee', 'dmz', 'internal', 'restricted', 'perimeter', 'management']

export default function NetworkEditor({
  network,
  selectedNodeId,
  selectedEdge,
  onAddDevice,
  onUpdateDevice,
  onDeleteDevice,
  onAddConnection,
  onUpdateConnection,
  onDeleteConnection,
  onSetCompromised,
  compromisedId,
  onClose,
}) {
  const [activeTab, setActiveTab] = useState('device') // 'device' | 'connection'

  // Device form state
  const [deviceForm, setDeviceForm] = useState({
    id: '',
    name: '',
    type: 'server',
    criticality: 3,
    zone: 'internal',
  })
  const [isEditingDevice, setIsEditingDevice] = useState(false)

  // Connection form state
  const [connForm, setConnForm] = useState({
    source: '',
    target: '',
    protocol: 'HTTPS',
    allowed: true,
    business_critical: false,
    disruption_cost: 1.0,
  })
  const [isEditingConn, setIsEditingConn] = useState(false)
  const [formError, setFormError] = useState('')

  // Sync selected node from graph into form
  useEffect(() => {
    if (selectedNodeId && network?.nodes) {
      const node = network.nodes.find((n) => n.id === selectedNodeId)
      if (node) {
        setDeviceForm({
          id: node.id,
          name: node.name || node.id,
          type: node.type || 'server',
          criticality: node.criticality || 1,
          zone: node.zone || 'internal',
        })
        setIsEditingDevice(true)
        setActiveTab('device')
        setFormError('')
      }
    }
  }, [selectedNodeId, network])

  // Sync selected edge from graph into form
  useEffect(() => {
    if (selectedEdge && network?.edges) {
      const edge = network.edges.find((e) => e.source === selectedEdge.source && e.target === selectedEdge.target)
      if (edge) {
        setConnForm({
          source: edge.source,
          target: edge.target,
          protocol: edge.protocol || 'TCP',
          allowed: edge.allowed !== undefined ? edge.allowed : true,
          business_critical: !!edge.business_critical,
          disruption_cost: edge.disruption_cost !== undefined ? edge.disruption_cost : 1.0,
        })
        setIsEditingConn(true)
        setActiveTab('connection')
        setFormError('')
      }
    }
  }, [selectedEdge, network])

  const resetDeviceForm = () => {
    setDeviceForm({ id: '', name: '', type: 'server', criticality: 3, zone: 'internal' })
    setIsEditingDevice(false)
    setFormError('')
  }

  const resetConnForm = () => {
    setConnForm({
      source: network?.nodes?.[0]?.id || '',
      target: network?.nodes?.[1]?.id || '',
      protocol: 'HTTPS',
      allowed: true,
      business_critical: false,
      disruption_cost: 1.0,
    })
    setIsEditingConn(false)
    setFormError('')
  }

  const handleDeviceSubmit = async (e) => {
    e.preventDefault()
    setFormError('')
    if (!deviceForm.name.trim()) {
      setFormError('Device name is required')
      return
    }

    if (isEditingDevice) {
      try {
        await onUpdateDevice(deviceForm.id, {
          name: deviceForm.name.trim(),
          type: deviceForm.type,
          criticality: Number(deviceForm.criticality),
          zone: deviceForm.zone.trim(),
        })
      } catch (err) {
        setFormError(err.message)
      }
    } else {
      if (!deviceForm.id.trim()) {
        setFormError('Device ID is required')
        return
      }
      try {
        await onAddDevice({
          id: deviceForm.id.trim(),
          name: deviceForm.name.trim(),
          type: deviceForm.type,
          criticality: Number(deviceForm.criticality),
          zone: deviceForm.zone.trim(),
        })
        resetDeviceForm()
      } catch (err) {
        setFormError(err.message)
      }
    }
  }

  const handleConnSubmit = async (e) => {
    e.preventDefault()
    setFormError('')
    if (!connForm.source || !connForm.target) {
      setFormError('Source and target devices are required')
      return
    }
    if (connForm.source === connForm.target) {
      setFormError('Self-loop connections are not allowed')
      return
    }

    if (isEditingConn) {
      try {
        await onUpdateConnection(connForm.source, connForm.target, {
          protocol: connForm.protocol,
          allowed: connForm.allowed,
          business_critical: connForm.business_critical,
          disruption_cost: Number(connForm.disruption_cost),
        })
      } catch (err) {
        setFormError(err.message)
      }
    } else {
      try {
        await onAddConnection({
          source: connForm.source,
          target: connForm.target,
          protocol: connForm.protocol,
          allowed: connForm.allowed,
          business_critical: connForm.business_critical,
          disruption_cost: Number(connForm.disruption_cost),
        })
        resetConnForm()
      } catch (err) {
        setFormError(err.message)
      }
    }
  }

  const nodes = network?.nodes || []

  return (
    <div className="border-b border-white/5 bg-[#12161c]">
      <div className="flex items-center justify-between border-b border-white/5 px-4 py-2">
        <div className="flex gap-2">
          <button
            onClick={() => { setActiveTab('device'); setFormError('') }}
            className={`rounded px-2.5 py-1 text-xs font-medium transition ${
              activeTab === 'device' ? 'bg-white/10 text-white' : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            {isEditingDevice ? 'Edit Device' : 'Add Device'}
          </button>
          <button
            onClick={() => { setActiveTab('connection'); setFormError('') }}
            className={`rounded px-2.5 py-1 text-xs font-medium transition ${
              activeTab === 'connection' ? 'bg-white/10 text-white' : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            {isEditingConn ? 'Edit Connection' : 'Add Connection'}
          </button>
        </div>
        <button
          onClick={onClose}
          className="text-xs text-zinc-500 hover:text-zinc-300"
          title="Close editor panel"
        >
          ✕
        </button>
      </div>

      <div className="p-4">
        {formError && (
          <div className="mb-3 rounded bg-red-500/10 p-2 text-xs text-red-400">
            {formError}
          </div>
        )}

        {/* DEVICE FORM */}
        {activeTab === 'device' && (
          <form onSubmit={handleDeviceSubmit} className="space-y-3">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">ID</label>
                <input
                  type="text"
                  disabled={isEditingDevice}
                  value={deviceForm.id}
                  onChange={(e) => setDeviceForm({ ...deviceForm, id: e.target.value })}
                  placeholder="e.g. srv_finance"
                  className="w-full rounded bg-white/5 px-2 py-1 text-xs text-zinc-100 outline-none disabled:opacity-40"
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Name</label>
                <input
                  type="text"
                  value={deviceForm.name}
                  onChange={(e) => setDeviceForm({ ...deviceForm, name: e.target.value })}
                  placeholder="e.g. Finance App"
                  className="w-full rounded bg-white/5 px-2 py-1 text-xs text-zinc-100 outline-none"
                  required
                />
              </div>
            </div>

            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Type</label>
                <select
                  value={deviceForm.type}
                  onChange={(e) => setDeviceForm({ ...deviceForm, type: e.target.value })}
                  className="w-full rounded bg-white/5 px-1.5 py-1 text-xs text-zinc-100 outline-none"
                >
                  {DEVICE_TYPES.map((t) => (
                    <option key={t} value={t} className="bg-zinc-900">{t}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Criticality (1-5)</label>
                <select
                  value={deviceForm.criticality}
                  onChange={(e) => setDeviceForm({ ...deviceForm, criticality: Number(e.target.value) })}
                  className="w-full rounded bg-white/5 px-1.5 py-1 text-xs text-zinc-100 outline-none font-mono"
                >
                  {[1, 2, 3, 4, 5].map((c) => (
                    <option key={c} value={c} className="bg-zinc-900">{c} {c >= 4 ? '★' : ''}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Zone</label>
                <input
                  type="text"
                  list="zones-list"
                  value={deviceForm.zone}
                  onChange={(e) => setDeviceForm({ ...deviceForm, zone: e.target.value })}
                  className="w-full rounded bg-white/5 px-2 py-1 text-xs text-zinc-100 outline-none"
                />
                <datalist id="zones-list">
                  {ZONES.map((z) => (
                    <option key={z} value={z} />
                  ))}
                </datalist>
              </div>
            </div>

            <div className="flex items-center justify-between pt-1">
              <div className="flex gap-2">
                <button
                  type="submit"
                  className="rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500"
                >
                  {isEditingDevice ? 'Update Device' : '+ Add Device'}
                </button>
                {isEditingDevice && (
                  <button
                    type="button"
                    onClick={resetDeviceForm}
                    className="rounded bg-white/5 px-2.5 py-1 text-xs text-zinc-400 hover:text-white"
                  >
                    New
                  </button>
                )}
              </div>

              {isEditingDevice && (
                <div className="flex gap-1.5">
                  <button
                    type="button"
                    onClick={() => onSetCompromised(deviceForm.id)}
                    className={`rounded px-2 py-1 text-xs ${
                      compromisedId === deviceForm.id
                        ? 'bg-red-500/20 text-red-300'
                        : 'bg-white/5 text-zinc-400 hover:text-red-300'
                    }`}
                    title="Designate as compromised starting point"
                  >
                    Set Compromised
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (window.confirm(`Delete device '${deviceForm.name}' (${deviceForm.id})?`)) {
                        onDeleteDevice(deviceForm.id)
                        resetDeviceForm()
                      }
                    }}
                    className="rounded bg-red-500/10 px-2 py-1 text-xs text-red-400 hover:bg-red-500/20"
                  >
                    Delete
                  </button>
                </div>
              )}
            </div>
          </form>
        )}

        {/* CONNECTION FORM */}
        {activeTab === 'connection' && (
          <form onSubmit={handleConnSubmit} className="space-y-3">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Source (Origin)</label>
                <select
                  disabled={isEditingConn}
                  value={connForm.source}
                  onChange={(e) => setConnForm({ ...connForm, source: e.target.value })}
                  className="w-full rounded bg-white/5 px-2 py-1 text-xs text-zinc-100 outline-none disabled:opacity-40"
                  required
                >
                  <option value="">Select source...</option>
                  {nodes.map((n) => (
                    <option key={n.id} value={n.id} className="bg-zinc-900">{n.name} ({n.id})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Target (Destination)</label>
                <select
                  disabled={isEditingConn}
                  value={connForm.target}
                  onChange={(e) => setConnForm({ ...connForm, target: e.target.value })}
                  className="w-full rounded bg-white/5 px-2 py-1 text-xs text-zinc-100 outline-none disabled:opacity-40"
                  required
                >
                  <option value="">Select target...</option>
                  {nodes.map((n) => (
                    <option key={n.id} value={n.id} className="bg-zinc-900">{n.name} ({n.id})</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Protocol</label>
                <input
                  type="text"
                  list="proto-list"
                  value={connForm.protocol}
                  onChange={(e) => setConnForm({ ...connForm, protocol: e.target.value })}
                  className="w-full rounded bg-white/5 px-2 py-1 text-xs text-zinc-100 outline-none"
                  required
                />
                <datalist id="proto-list">
                  {PROTOCOLS.map((p) => (
                    <option key={p} value={p} />
                  ))}
                </datalist>
              </div>

              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Traffic Status</label>
                <select
                  value={connForm.allowed ? 'allowed' : 'blocked'}
                  onChange={(e) => setConnForm({ ...connForm, allowed: e.target.value === 'allowed' })}
                  className="w-full rounded bg-white/5 px-2 py-1 text-xs text-zinc-100 outline-none font-mono"
                >
                  <option value="allowed" className="bg-zinc-900">Allowed</option>
                  <option value="blocked" className="bg-zinc-900">Blocked</option>
                </select>
              </div>

              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Disruption Cost</label>
                <input
                  type="number"
                  step="0.5"
                  min="0"
                  value={connForm.disruption_cost}
                  onChange={(e) => setConnForm({ ...connForm, disruption_cost: Number(e.target.value) })}
                  className="w-full rounded bg-white/5 px-2 py-1 text-xs text-zinc-100 outline-none font-mono"
                />
              </div>
            </div>

            <div className="flex items-center gap-2 pt-0.5">
              <label className="flex items-center gap-1.5 text-xs text-zinc-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={connForm.business_critical}
                  onChange={(e) => setConnForm({ ...connForm, business_critical: e.target.checked })}
                  className="accent-sky-500 rounded"
                />
                Business Critical Link
              </label>
            </div>

            <div className="flex items-center justify-between pt-1">
              <div className="flex gap-2">
                <button
                  type="submit"
                  className="rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500"
                >
                  {isEditingConn ? 'Update Link' : '+ Add Link'}
                </button>
                {isEditingConn && (
                  <button
                    type="button"
                    onClick={resetConnForm}
                    className="rounded bg-white/5 px-2.5 py-1 text-xs text-zinc-400 hover:text-white"
                  >
                    New
                  </button>
                )}
              </div>

              {isEditingConn && (
                <button
                  type="button"
                  onClick={() => {
                    if (window.confirm(`Delete connection ${connForm.source} → ${connForm.target}?`)) {
                      onDeleteConnection(connForm.source, connForm.target)
                      resetConnForm()
                    }
                  }}
                  className="rounded bg-red-500/10 px-2 py-1 text-xs text-red-400 hover:bg-red-500/20"
                >
                  Delete Link
                </button>
              )}
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
