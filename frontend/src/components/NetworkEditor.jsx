import { useState, useEffect } from 'react'
import { api } from '../api'

export const MAJOR_DEVICE_CATEGORIES = [
  { value: 'endpoint', label: 'Endpoint (workstation, laptop, desktop)' },
  { value: 'server', label: 'Server (application, web, service)' },
  { value: 'database', label: 'Database (relational, distributed data store)' },
  { value: 'network_device', label: 'Network Device (router, switch, hub)' },
  { value: 'firewall', label: 'Firewall (perimeter, security gateway)' },
  { value: 'wireless_access_point', label: 'Wireless Access Point (Wi-Fi AP)' },
  { value: 'cloud_infrastructure', label: 'Cloud Infrastructure (compute, VPC)' },
  { value: 'security_system', label: 'Security System (IDS/IPS, SIEM)' },
  { value: 'iot_device', label: 'IoT Device (cameras, sensors, controllers)' },
  { value: 'external', label: 'External (internet endpoint, third-party)' },
  { value: 'unknown', label: 'Unknown (unclassified device)' },
]

const PROTOCOLS = ['HTTPS', 'SSH', 'SQL', 'TCP', 'HTTP', 'RDP', 'DNS', 'SMB']
const ZONES = ['internal', 'restricted', 'dmz', 'employee', 'perimeter', 'management', 'external']

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
    inferred_role: '',
    manual_override: false,
    hostname: '',
    discovery_source: 'manual',
    ip_addresses_str: '',
    services: [],
    vulnerabilities: [],
  })
  const [isEditingDevice, setIsEditingDevice] = useState(false)
  const [recommendation, setRecommendation] = useState(null)
  const [loadingRec, setLoadingRec] = useState(false)

  // Service modal / quick add state
  const [newService, setNewService] = useState({ name: '', port: '', protocol: 'tcp', version: '' })
  const [newVuln, setNewVuln] = useState({
    id: '',
    title: '',
    severity: 'high',
    cvss_score: '7.5',
    service_port: '',
    exploit_available: false,
    confidence: 'confirmed',
    evidence: '',
    cwe: '',
  })

  // Connection form state
  const [connForm, setConnForm] = useState({
    source: '',
    target: '',
    protocol: 'HTTPS',
    allowed: true,
    policy_status: 'allowed',
    business_critical: false,
    disruption_cost: 1.0,
    port: '',
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
          type: node.type || 'unknown',
          criticality: node.criticality || 2,
          zone: node.zone || 'internal',
          inferred_role: node.inferred_role || '',
          manual_override: !!node.manual_override,
          hostname: node.hostname || '',
          discovery_source: node.discovery_source || 'manual',
          ip_addresses_str: (node.ip_addresses || []).join(', '),
          services: node.services || [],
          vulnerabilities: node.vulnerabilities || [],
        })
        setIsEditingDevice(true)
        setActiveTab('device')
        setFormError('')

        // Fetch deterministic recommendation
        fetchRecommendation(node.id)
        return
      }
    }
    if (!selectedNodeId) {
      setIsEditingDevice(false)
      setRecommendation(null)
    }
  }, [selectedNodeId, network])

  // Sync selected edge from graph into form
  useEffect(() => {
    if (selectedEdge && network?.edges) {
      const edge = network.edges.find((e) => e.source === selectedEdge.source && e.target === selectedEdge.target)
      if (edge) {
        const policyStatus = edge.policy_status || (edge.allowed ? 'allowed' : 'denied')
        setConnForm({
          source: edge.source,
          target: edge.target,
          protocol: edge.protocol || 'TCP',
          allowed: edge.allowed !== undefined ? edge.allowed : true,
          policy_status: policyStatus,
          business_critical: !!edge.business_critical,
          disruption_cost: edge.disruption_cost !== undefined ? edge.disruption_cost : 1.0,
          port: edge.port ? String(edge.port) : '',
        })
        setIsEditingConn(true)
        setActiveTab('connection')
        setFormError('')
      }
    }
  }, [selectedEdge, network])

  async function fetchRecommendation(devId) {
    if (!devId) return
    setLoadingRec(true)
    try {
      const rec = await api.getCriticalityRecommendation(devId)
      setRecommendation(rec)
    } catch {
      setRecommendation(null)
    } finally {
      setLoadingRec(false)
    }
  }

  const handleDeviceSubmit = async (e) => {
    e.preventDefault()
    setFormError('')
    if (!deviceForm.name.trim()) {
      setFormError('Device name is required')
      return
    }

    const ips = deviceForm.ip_addresses_str
      ? deviceForm.ip_addresses_str.split(',').map((s) => s.trim()).filter(Boolean)
      : []

    if (isEditingDevice) {
      try {
        await onUpdateDevice(deviceForm.id, {
          name: deviceForm.name.trim(),
          type: deviceForm.type,
          criticality: Number(deviceForm.criticality),
          zone: deviceForm.zone.trim(),
          inferred_role: deviceForm.inferred_role.trim() || null,
          manual_override: deviceForm.manual_override,
          hostname: deviceForm.hostname.trim() || null,
          ip_addresses: ips,
          services: deviceForm.services || [],
          vulnerabilities: deviceForm.vulnerabilities || [],
        })
        onClose?.()
      } catch (err) {
        setFormError(err.message)
      }
    } else {
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
          inferred_role: deviceForm.inferred_role.trim() || null,
          manual_override: deviceForm.manual_override,
          hostname: deviceForm.hostname.trim() || null,
          discovery_source: 'manual',
          ip_addresses: ips,
          services: deviceForm.services || [],
          vulnerabilities: deviceForm.vulnerabilities || [],
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

    const portNum = connForm.port ? parseInt(connForm.port, 10) : undefined

    if (isEditingConn) {
      try {
        await onUpdateConnection(connForm.source, connForm.target, {
          protocol: connForm.protocol,
          allowed: connForm.policy_status === 'allowed',
          policy_status: connForm.policy_status,
          business_critical: connForm.business_critical,
          disruption_cost: Number(connForm.disruption_cost),
          port: portNum,
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
          allowed: connForm.policy_status === 'allowed',
          policy_status: connForm.policy_status,
          business_critical: connForm.business_critical,
          disruption_cost: Number(connForm.disruption_cost),
          port: portNum,
        })
        onClose?.()
      } catch (err) {
        setFormError(err.message)
      }
    }
  }

  const nodes = network?.nodes || []

  return (
    <div className="flex flex-col h-full select-none">
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
            <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
              <span>{isEditingDevice ? `Editing: ${deviceForm.name}` : 'Create New Device'}</span>
              {isEditingDevice && (
                <span className={`px-1.5 py-0.5 rounded text-[10px] ${deviceForm.manual_override ? 'bg-amber-500/10 text-amber-300 border border-amber-500/20' : 'bg-sky-500/10 text-sky-300 border border-sky-500/20'}`}>
                  {deviceForm.manual_override ? 'Manual Override 🔒' : 'Automatic Recommendation'}
                </span>
              )}
            </div>

            <div>
              <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">
                Device Name
              </label>
              <input
                type="text"
                value={deviceForm.name}
                onChange={(e) => setDeviceForm({ ...deviceForm, name: e.target.value })}
                placeholder="e.g. Core Database Cluster"
                className="w-full rounded bg-white/5 border border-white/10 px-2.5 py-1.5 text-xs text-zinc-100 outline-none focus:border-sky-500"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-2.5">
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Category</label>
                <select
                  value={deviceForm.type}
                  onChange={(e) => setDeviceForm({ ...deviceForm, type: e.target.value })}
                  className="w-full rounded bg-white/5 border border-white/10 px-2 py-1.5 text-xs text-zinc-100 outline-none"
                >
                  {MAJOR_DEVICE_CATEGORIES.map((c) => (
                    <option key={c.value} value={c.value} className="bg-zinc-900">{c.label}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-wider text-zinc-400">
                  <span>Criticality (1-5)</span>
                  {recommendation && (
                    <span className="text-sky-400 font-mono text-[9px]">Rec: C{recommendation.recommended_criticality}</span>
                  )}
                </label>
                <select
                  value={deviceForm.criticality}
                  onChange={(e) => setDeviceForm({ ...deviceForm, criticality: Number(e.target.value), manual_override: true })}
                  className="w-full rounded bg-white/5 border border-white/10 px-2 py-1.5 text-xs text-zinc-100 outline-none font-mono"
                >
                  {[1, 2, 3, 4, 5].map((c) => (
                    <option key={c} value={c} className="bg-zinc-900">
                      C{c} {c >= 4 ? '★ High Value' : ''}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Recommendation Explanation Card */}
            {recommendation && (
              <div className="rounded border border-sky-500/20 bg-sky-500/5 p-2.5 text-[11px] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-sky-300">
                    Auto-Criticality Analysis
                  </span>
                  <span className="text-[10px] font-mono px-1 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20 capitalize">
                    {recommendation.confidence} confidence
                  </span>
                </div>
                <p className="text-zinc-300 text-[10.5px] leading-relaxed">
                  {recommendation.explanation}
                </p>
                {recommendation.missing_information?.length > 0 && (
                  <div className="mt-1 text-[10px] text-zinc-400 border-t border-white/5 pt-1">
                    <span className="text-amber-400/80 font-medium">Missing context: </span>
                    {recommendation.missing_information.join(' ')}
                  </div>
                )}
                {deviceForm.criticality !== recommendation.recommended_criticality && (
                  <div className="pt-1 flex items-center justify-between">
                    <span className="text-[10px] text-amber-300/90">Manually overridden (C{deviceForm.criticality})</span>
                    <button
                      type="button"
                      onClick={() => setDeviceForm({ ...deviceForm, criticality: recommendation.recommended_criticality, manual_override: false })}
                      className="text-[10px] underline text-sky-400 hover:text-sky-300"
                    >
                      Reset to Recommended (C{recommendation.recommended_criticality})
                    </button>
                  </div>
                )}
              </div>
            )}

            <div className="grid grid-cols-2 gap-2.5">
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Network Zone</label>
                <input
                  type="text"
                  list="zones-list"
                  value={deviceForm.zone}
                  onChange={(e) => setDeviceForm({ ...deviceForm, zone: e.target.value })}
                  placeholder="e.g. internal, dmz"
                  className="w-full rounded bg-white/5 border border-white/10 px-2.5 py-1.5 text-xs text-zinc-100 outline-none"
                />
                <datalist id="zones-list">
                  {ZONES.map((z) => (
                    <option key={z} value={z} />
                  ))}
                </datalist>
              </div>

              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Inferred Role</label>
                <input
                  type="text"
                  value={deviceForm.inferred_role}
                  onChange={(e) => setDeviceForm({ ...deviceForm, inferred_role: e.target.value })}
                  placeholder="e.g. Domain Controller"
                  className="w-full rounded bg-white/5 border border-white/10 px-2.5 py-1.5 text-xs text-zinc-100 outline-none"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2.5">
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Hostname / FQDN</label>
                <input
                  type="text"
                  value={deviceForm.hostname}
                  onChange={(e) => setDeviceForm({ ...deviceForm, hostname: e.target.value })}
                  placeholder="e.g. dc1.corp.internal"
                  className="w-full rounded bg-white/5 border border-white/10 px-2.5 py-1.5 text-xs text-zinc-100 outline-none"
                />
              </div>

              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">IP Address(es)</label>
                <input
                  type="text"
                  value={deviceForm.ip_addresses_str}
                  onChange={(e) => setDeviceForm({ ...deviceForm, ip_addresses_str: e.target.value })}
                  placeholder="Comma-separated IPs"
                  className="w-full rounded bg-white/5 border border-white/10 px-2.5 py-1.5 text-xs text-zinc-100 outline-none font-mono"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2.5 pt-1">
              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Device ID</label>
                <input
                  type="text"
                  disabled={isEditingDevice}
                  value={deviceForm.id}
                  onChange={(e) => setDeviceForm({ ...deviceForm, id: e.target.value })}
                  placeholder="Auto-generated"
                  className="w-full rounded bg-white/5 border border-white/10 px-2.5 py-1.5 text-xs text-zinc-100 outline-none disabled:opacity-40 font-mono"
                />
              </div>
              <div className="flex items-center pt-4">
                <label className="flex items-center gap-1.5 text-xs text-zinc-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={deviceForm.manual_override}
                    onChange={(e) => setDeviceForm({ ...deviceForm, manual_override: e.target.checked })}
                    className="accent-sky-500 rounded"
                  />
                  <span>Lock Manual Override</span>
                </label>
              </div>
            </div>

            {/* SERVICES SECTION */}
            <div className="border-t border-white/10 pt-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-300">
                  Configured Services ({deviceForm.services?.length || 0})
                </span>
              </div>
              <div className="space-y-1.5 mb-2.5">
                {(!deviceForm.services || deviceForm.services.length === 0) ? (
                  <p className="text-[11px] text-zinc-500 italic">No services registered on this host.</p>
                ) : (
                  deviceForm.services.map((s, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-white/[0.03] border border-white/5 rounded px-2.5 py-1 text-xs">
                      <div>
                        <span className="font-semibold text-zinc-200">{s.name}</span>
                        <span className="text-zinc-400 font-mono ml-2">:{s.port}/{s.protocol}</span>
                        {s.version && <span className="text-zinc-500 text-[10px] ml-2">({s.version})</span>}
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          const updated = deviceForm.services.filter((_, i) => i !== idx)
                          setDeviceForm({ ...deviceForm, services: updated })
                        }}
                        className="text-red-400 hover:text-red-300 text-xs px-1"
                      >
                        ✕
                      </button>
                    </div>
                  ))
                )}
              </div>
              {/* Add Service Inputs */}
              <div className="grid grid-cols-4 gap-1.5 bg-black/20 p-2 rounded border border-white/5 text-xs">
                <input
                  type="text"
                  placeholder="Service (e.g. https)"
                  value={newService.name}
                  onChange={(e) => setNewService({ ...newService, name: e.target.value })}
                  className="rounded bg-white/5 border border-white/10 px-2 py-1 text-zinc-200 text-xs outline-none"
                />
                <input
                  type="number"
                  placeholder="Port (e.g. 443)"
                  value={newService.port}
                  onChange={(e) => setNewService({ ...newService, port: e.target.value })}
                  className="rounded bg-white/5 border border-white/10 px-2 py-1 text-zinc-200 text-xs outline-none font-mono"
                />
                <input
                  type="text"
                  placeholder="Version / Banner"
                  value={newService.version}
                  onChange={(e) => setNewService({ ...newService, version: e.target.value })}
                  className="rounded bg-white/5 border border-white/10 px-2 py-1 text-zinc-200 text-xs outline-none"
                />
                <button
                  type="button"
                  onClick={() => {
                    if (!newService.name.trim() || !newService.port) return
                    const port = parseInt(newService.port, 10)
                    if (isNaN(port) || port < 1 || port > 65535) return
                    const item = {
                      name: newService.name.trim().toLowerCase(),
                      port,
                      protocol: newService.protocol || 'tcp',
                      version: newService.version.trim() || null,
                      status: 'active',
                    }
                    setDeviceForm({
                      ...deviceForm,
                      services: [...(deviceForm.services || []), item],
                    })
                    setNewService({ name: '', port: '', protocol: 'tcp', version: '' })
                  }}
                  className="rounded bg-white/10 text-zinc-200 hover:bg-white/20 text-xs font-medium"
                >
                  + Add Service
                </button>
              </div>
            </div>

            {/* VULNERABILITIES SECTION */}
            <div className="border-t border-white/10 pt-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-300">
                  Known Vulnerabilities ({deviceForm.vulnerabilities?.length || 0})
                </span>
              </div>
              <div className="space-y-1.5 mb-2.5">
                {(!deviceForm.vulnerabilities || deviceForm.vulnerabilities.length === 0) ? (
                  <p className="text-[11px] text-zinc-500 italic">No vulnerability findings associated.</p>
                ) : (
                  deviceForm.vulnerabilities.map((v, idx) => (
                    <div key={idx} className="bg-white/[0.03] border border-white/5 rounded p-2 text-xs">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                            v.severity === 'critical' ? 'bg-red-500/20 text-red-300 border border-red-500/40' :
                            v.severity === 'high' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                            'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40'
                          }`}>
                            {v.severity} {v.cvss_score ? `(${v.cvss_score})` : ''}
                          </span>
                          <span className="font-semibold text-zinc-200 font-mono">{v.id}</span>
                          {v.service_port && (
                            <span className="text-zinc-400 font-mono text-[10px]">port {v.service_port}</span>
                          )}
                          {v.exploit_available && (
                            <span className="px-1 py-0.2 bg-red-950/60 text-red-400 rounded text-[9px] border border-red-800">
                              Exploit Available
                            </span>
                          )}
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            const updated = deviceForm.vulnerabilities.filter((_, i) => i !== idx)
                            setDeviceForm({ ...deviceForm, vulnerabilities: updated })
                          }}
                          className="text-red-400 hover:text-red-300 text-xs px-1"
                        >
                          ✕
                        </button>
                      </div>
                      <div className="text-zinc-300 mt-1">{v.title}</div>
                      {v.evidence && <div className="text-zinc-500 text-[10px] mt-0.5 italic">Evidence: {v.evidence}</div>}
                    </div>
                  ))
                )}
              </div>
              {/* Add Vuln Inputs */}
              <div className="space-y-1.5 bg-black/20 p-2 rounded border border-white/5 text-xs">
                <div className="grid grid-cols-3 gap-1.5">
                  <input
                    type="text"
                    placeholder="CVE ID (e.g. CVE-2023-1234)"
                    value={newVuln.id}
                    onChange={(e) => setNewVuln({ ...newVuln, id: e.target.value })}
                    className="rounded bg-white/5 border border-white/10 px-2 py-1 text-zinc-200 text-xs outline-none font-mono"
                  />
                  <select
                    value={newVuln.severity}
                    onChange={(e) => setNewVuln({ ...newVuln, severity: e.target.value })}
                    className="rounded bg-white/5 border border-white/10 px-2 py-1 text-zinc-200 text-xs outline-none"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <input
                    type="number"
                    step="0.1"
                    placeholder="CVSS (0-10)"
                    value={newVuln.cvss_score}
                    onChange={(e) => setNewVuln({ ...newVuln, cvss_score: e.target.value })}
                    className="rounded bg-white/5 border border-white/10 px-2 py-1 text-zinc-200 text-xs outline-none font-mono"
                  />
                </div>
                <div className="grid grid-cols-2 gap-1.5">
                  <input
                    type="text"
                    placeholder="Vulnerability Title / Description"
                    value={newVuln.title}
                    onChange={(e) => setNewVuln({ ...newVuln, title: e.target.value })}
                    className="rounded bg-white/5 border border-white/10 px-2 py-1 text-zinc-200 text-xs outline-none"
                  />
                  <input
                    type="number"
                    placeholder="Target Port (optional)"
                    value={newVuln.service_port}
                    onChange={(e) => setNewVuln({ ...newVuln, service_port: e.target.value })}
                    className="rounded bg-white/5 border border-white/10 px-2 py-1 text-zinc-200 text-xs outline-none font-mono"
                  />
                </div>
                <div className="flex items-center justify-between pt-1">
                  <label className="flex items-center gap-1.5 text-zinc-300 text-xs cursor-pointer">
                    <input
                      type="checkbox"
                      checked={newVuln.exploit_available}
                      onChange={(e) => setNewVuln({ ...newVuln, exploit_available: e.target.checked })}
                      className="accent-red-500 rounded"
                    />
                    <span>Public Exploit Available</span>
                  </label>
                  <button
                    type="button"
                    onClick={() => {
                      if (!newVuln.id.trim() || !newVuln.title.trim()) return
                      const portNum = newVuln.service_port ? parseInt(newVuln.service_port, 10) : null
                      const cvss = newVuln.cvss_score ? parseFloat(newVuln.cvss_score) : null
                      const item = {
                        id: newVuln.id.trim(),
                        title: newVuln.title.trim(),
                        severity: newVuln.severity,
                        cvss_score: cvss,
                        service_port: portNum,
                        exploit_available: newVuln.exploit_available,
                        confidence: newVuln.confidence || 'confirmed',
                        evidence: newVuln.evidence || 'Manual security assessment',
                        cwe: newVuln.cwe || null,
                      }
                      setDeviceForm({
                        ...deviceForm,
                        vulnerabilities: [...(deviceForm.vulnerabilities || []), item],
                      })
                      setNewVuln({
                        id: '',
                        title: '',
                        severity: 'high',
                        cvss_score: '7.5',
                        service_port: '',
                        exploit_available: false,
                        confidence: 'confirmed',
                        evidence: '',
                        cwe: '',
                      })
                    }}
                    className="rounded bg-red-500/20 text-red-300 border border-red-500/30 hover:bg-red-500/30 px-3 py-1 text-xs font-medium"
                  >
                    + Add Vulnerability
                  </button>
                </div>
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

            <div className="grid grid-cols-3 gap-2.5">
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
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Port (Opt)</label>
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={connForm.port}
                  onChange={(e) => setConnForm({ ...connForm, port: e.target.value })}
                  placeholder="e.g. 443"
                  className="w-full rounded bg-white/5 border border-white/10 px-2.5 py-1.5 text-xs text-zinc-100 outline-none font-mono"
                />
              </div>

              <div>
                <label className="mb-1 block text-[10px] uppercase tracking-wider text-zinc-400">Policy Status</label>
                <select
                  value={connForm.policy_status}
                  onChange={(e) => setConnForm({
                    ...connForm,
                    policy_status: e.target.value,
                    allowed: e.target.value === 'allowed',
                  })}
                  className="w-full rounded bg-white/5 border border-white/10 px-2 py-1.5 text-xs text-zinc-100 outline-none font-mono"
                >
                  <option value="allowed" className="bg-zinc-900">Allowed (Traversable)</option>
                  <option value="denied" className="bg-zinc-900">Denied (Blocked)</option>
                  <option value="unknown" className="bg-zinc-900">Unknown Policy (Observed only)</option>
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
          </form>
        )}
      </div>
    </div>
  )
}
