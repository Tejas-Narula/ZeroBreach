import { useState, useEffect } from 'react'

const DEVICE_TYPES = ['server', 'database', 'laptop', 'workstation', 'firewall', 'router']
const PROTOCOLS = ['HTTPS', 'SSH', 'SQL', 'TCP', 'HTTP', 'RDP']
const ZONES = ['internal', 'restricted', 'dmz', 'employee', 'perimeter', 'management']

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
  const [activeTab, setActiveTab] = useState(selectedEdge ? 'connection' : 'device')

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
        return
      }
    }
    // If no node selected, stay in new device mode
    if (!selectedNodeId) {
      setIsEditingDevice(false)
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
        // Saving unselects current device & closes/resets editor
        onClose?.()
      } catch (err) {
        setFormError(err.message)
      }
    } else {
      // Auto-generate ID if empty: e.g. server_3
      let generatedId = deviceForm.id.trim()
      if (!generatedId) {
        const prefix = deviceForm.type || 'node'
        let counter = (network?.nodes?.length || 0) + 1
        generatedId = `${prefix}_${counter}`
        while (network?.nodes?.some((n) => n.id === generatedId)) {
          counter++
          generatedId = `${prefix}_${counter}`
        }
      }

      try {
        await onAddDevice({
          id: generatedId,
          name: deviceForm.name.trim(),
          type: deviceForm.type,
          criticality: Number(deviceForm.criticality),
          zone: deviceForm.zone.trim(),
        })
        onClose?.()
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
        onClose?.()
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
        onClose?.()
      } catch (err) {
        setFormError(err.message)
      }
    }
  }

  const nodes = network?.nodes || []

  return (
    <div className="flex flex-col h-full">
      {/* Tab Switcher & Close */}
      <div className="flex items-center justify-between border-b border-white/5 px-4 py-2.5 bg-white/[0.02]">
        <div className="flex gap-1.5">
          <button
            type="button"
            onClick={() => { setActiveTab('device'); setFormError('') }}
            className={`rounded px-2.5 py-1 text-xs font-medium transition ${
              activeTab === 'device' ? 'bg-sky-600 text-white' : 'text-zinc-400 hover:text-zinc-200 bg-white/5'
            }`}
          >
            {isEditingDevice ? 'Edit Device' : 'New Device'}
          </button>
          <button
            type="button"
            onClick={() => { setActiveTab('connection'); setFormError('') }}
            className={`rounded px-2.5 py-1 text-xs font-medium transition ${
              activeTab === 'connection' ? 'bg-sky-600 text-white' : 'text-zinc-400 hover:text-zinc-200 bg-white/5'
            }`}
          >
            {isEditingConn ? 'Edit Link' : 'New Link'}
          </button>
        </div>

        <button
          type="button"
          onClick={onClose}
          className="text-xs text-zinc-500 hover:text-zinc-200 px-1 py-0.5"
          title="Done / Deselect"
        >
          ✕ Done
        </button>
      </div>

      <div className="p-4 flex-1 overflow-y-auto space-y-4">
        {formError && (
          <div className="rounded bg-red-500/10 border border-red-500/20 p-2 text-xs text-red-400">
            {formError}
          </div>
        )}

        {/* DEVICE FORM */}
        {activeTab === 'device' && (
          <form onSubmit={handleDeviceSubmit} className="space-y-3.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
              {isEditingDevice ? `Editing: ${deviceForm.name}` : 'Create New Device'}
            </div>

            <div>
              <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">
                Device Name
              </label>
              <input
                type="text"
                value={deviceForm.name}
                onChange={(e) => setDeviceForm({ ...deviceForm, name: e.target.value })}
                placeholder="e.g. Core App Server"
                className="w-full rounded bg-white/5 border border-white/10 px-2.5 py-1.5 text-xs text-zinc-100 outline-none focus:border-sky-500"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-2.5">
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Type</label>
                <select
                  value={deviceForm.type}
                  onChange={(e) => setDeviceForm({ ...deviceForm, type: e.target.value })}
                  className="w-full rounded bg-white/5 border border-white/10 px-2 py-1.5 text-xs text-zinc-100 outline-none"
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
                  className="w-full rounded bg-white/5 border border-white/10 px-2 py-1.5 text-xs text-zinc-100 outline-none font-mono"
                >
                  {[1, 2, 3, 4, 5].map((c) => (
                    <option key={c} value={c} className="bg-zinc-900">
                      C{c} {c >= 4 ? '★ High Risk' : ''}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2.5">
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Zone</label>
                <input
                  type="text"
                  list="zones-list"
                  value={deviceForm.zone}
                  onChange={(e) => setDeviceForm({ ...deviceForm, zone: e.target.value })}
                  className="w-full rounded bg-white/5 border border-white/10 px-2.5 py-1.5 text-xs text-zinc-100 outline-none"
                />
                <datalist id="zones-list">
                  {ZONES.map((z) => (
                    <option key={z} value={z} />
                  ))}
                </datalist>
              </div>

              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">ID (Optional)</label>
                <input
                  type="text"
                  disabled={isEditingDevice}
                  value={deviceForm.id}
                  onChange={(e) => setDeviceForm({ ...deviceForm, id: e.target.value })}
                  placeholder="Auto-generated"
                  className="w-full rounded bg-white/5 border border-white/10 px-2.5 py-1.5 text-xs text-zinc-100 outline-none disabled:opacity-40 font-mono"
                />
              </div>
            </div>

            <div className="pt-2 flex flex-col gap-2">
              <button
                type="submit"
                className="w-full rounded bg-sky-600 py-1.5 text-xs font-medium text-white hover:bg-sky-500 transition"
              >
                {isEditingDevice ? 'Save & Close' : '+ Add Device'}
              </button>

              {isEditingDevice && (
                <div className="grid grid-cols-2 gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() => onSetCompromised(deviceForm.id)}
                    className={`rounded py-1.5 text-xs font-medium transition ${
                      compromisedId === deviceForm.id
                        ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                        : 'bg-white/5 text-zinc-300 hover:text-red-300 border border-white/5'
                    }`}
                  >
                    {compromisedId === deviceForm.id ? '★ Compromised' : 'Set Compromised'}
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      if (window.confirm(`Delete device '${deviceForm.name}' (${deviceForm.id})?`)) {
                        onDeleteDevice(deviceForm.id)
                        onClose?.()
                      }
                    }}
                    className="rounded bg-red-500/10 border border-red-500/20 py-1.5 text-xs text-red-400 hover:bg-red-500/20 transition"
                  >
                    Delete Device
                  </button>
                </div>
              )}
            </div>

            <p className="text-[10px] text-zinc-500 pt-2 border-t border-white/5">
              Tip: Drag any device from the left Device Palette directly onto the canvas to place it at that location.
            </p>
          </form>
        )}

        {/* CONNECTION FORM */}
        {activeTab === 'connection' && (
          <form onSubmit={handleConnSubmit} className="space-y-3.5">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
              {isEditingConn ? `Editing: ${connForm.source} → ${connForm.target}` : 'Create Directed Connection'}
            </div>

            <div className="grid grid-cols-2 gap-2.5">
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Source (Origin)</label>
                <select
                  disabled={isEditingConn}
                  value={connForm.source}
                  onChange={(e) => setConnForm({ ...connForm, source: e.target.value })}
                  className="w-full rounded bg-white/5 border border-white/10 px-2 py-1.5 text-xs text-zinc-100 outline-none disabled:opacity-40"
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
                  className="w-full rounded bg-white/5 border border-white/10 px-2 py-1.5 text-xs text-zinc-100 outline-none disabled:opacity-40"
                  required
                >
                  <option value="">Select target...</option>
                  {nodes.map((n) => (
                    <option key={n.id} value={n.id} className="bg-zinc-900">{n.name} ({n.id})</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2.5">
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Protocol</label>
                <input
                  type="text"
                  list="proto-list"
                  value={connForm.protocol}
                  onChange={(e) => setConnForm({ ...connForm, protocol: e.target.value })}
                  className="w-full rounded bg-white/5 border border-white/10 px-2.5 py-1.5 text-xs text-zinc-100 outline-none"
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
                  className="w-full rounded bg-white/5 border border-white/10 px-2 py-1.5 text-xs text-zinc-100 outline-none font-mono"
                >
                  <option value="allowed" className="bg-zinc-900">Allowed</option>
                  <option value="blocked" className="bg-zinc-900">Blocked</option>
                </select>
              </div>
            </div>

            <div>
              <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Disruption Cost</label>
              <input
                type="number"
                step="0.5"
                min="0"
                value={connForm.disruption_cost}
                onChange={(e) => setConnForm({ ...connForm, disruption_cost: Number(e.target.value) })}
                className="w-full rounded bg-white/5 border border-white/10 px-2.5 py-1.5 text-xs text-zinc-100 outline-none font-mono"
              />
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

            <div className="pt-2 flex flex-col gap-2">
              <button
                type="submit"
                className="w-full rounded bg-sky-600 py-1.5 text-xs font-medium text-white hover:bg-sky-500 transition"
              >
                {isEditingConn ? 'Save & Close' : '+ Add Connection'}
              </button>

              {isEditingConn && (
                <button
                  type="button"
                  onClick={() => {
                    if (window.confirm(`Delete connection ${connForm.source} → ${connForm.target}?`)) {
                      onDeleteConnection(connForm.source, connForm.target)
                      onClose?.()
                    }
                  }}
                  className="w-full rounded bg-red-500/10 border border-red-500/20 py-1.5 text-xs text-red-400 hover:bg-red-500/20 transition"
                >
                  Delete Connection
                </button>
              )}
            </div>

            <p className="text-[10px] text-zinc-500 pt-2 border-t border-white/5">
              Tip: You can also connect devices by clicking and holding on a device, dragging to another device, and releasing!
            </p>
          </form>
        )}
      </div>
    </div>
  )
}
