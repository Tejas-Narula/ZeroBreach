import { useState, useEffect } from 'react'
import { api } from '../api'
import {
  Icon,
  Tabs,
  Field,
  KV,
  CritBadge,
  PolicyBadge,
  ObservedBadge,
  SeverityBadge,
  Unknown,
  Empty,
} from './ui'
import { TYPE_IMAGE } from '../utils/graphStorage'

const MAJOR_DEVICE_CATEGORIES = [
  { value: 'endpoint', label: 'Endpoint (workstation, laptop, desktop)' },
  { value: 'server', label: 'Server (application, web, service)' },
  { value: 'database', label: 'Database (relational, distributed store)' },
  { value: 'network_device', label: 'Network Device (router, switch, relay)' },
  { value: 'firewall', label: 'Firewall (perimeter, security gateway)' },
  { value: 'wireless_access_point', label: 'Wireless Access Point (Wi-Fi AP)' },
  { value: 'cloud_infrastructure', label: 'Cloud Infrastructure (compute, VPC)' },
  { value: 'security_system', label: 'Security System (IDS/IPS, SIEM)' },
  { value: 'iot_device', label: 'IoT Device (cameras, sensors, controllers)' },
  { value: 'external', label: 'External (internet, third-party)' },
  { value: 'unknown', label: 'Unknown (unclassified host)' },
]

const PROTOCOLS = ['HTTPS', 'HTTP', 'SSH', 'SQL', 'TCP', 'UDP', 'DNS', 'RDP', 'SMB']
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
  onSelectNode,
  onSelectEdge,
}) {
  // Active sub-tab for device inspector: 'overview' | 'services' | 'vulns' | 'links'
  const [deviceTab, setDeviceTab] = useState('overview')
  const [isEditing, setIsEditing] = useState(false)
  const [isCreatingDevice, setIsCreatingDevice] = useState(false)
  const [isCreatingConn, setIsCreatingConn] = useState(false)

  // Recommendation state
  const [recommendation, setRecommendation] = useState(null)

  // Form error
  const [formError, setFormError] = useState('')

  // Device form
  const [devForm, setDevForm] = useState({
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

  // Quick-add service inline form
  const [showAddService, setShowAddService] = useState(false)
  const [newService, setNewService] = useState({ name: '', port: '', protocol: 'TCP', version: '' })

  // Quick-add vuln inline form
  const [showAddVuln, setShowAddVuln] = useState(false)
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

  // Connection form
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

  async function fetchRecommendation(devId) {
    if (!devId) return
    try {
      const rec = await api.getCriticalityRecommendation(devId)
      setRecommendation(rec)
    } catch {
      setRecommendation(null)
    }
  }

  // Synchronize selected node
  useEffect(() => {
    if (selectedNodeId && network?.nodes) {
      const node = network.nodes.find((n) => n.id === selectedNodeId)
      if (node) {
        setDevForm({
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
        setIsEditing(false)
        setIsCreatingDevice(false)
        setIsCreatingConn(false)
        setFormError('')
        fetchRecommendation(node.id)
        return
      }
    }
    setRecommendation(null)
  }, [selectedNodeId, network])

  // Synchronize selected edge
  useEffect(() => {
    if (selectedEdge && network?.edges) {
      const edge = network.edges.find((e) => e.source === selectedEdge.source && e.target === selectedEdge.target)
      if (edge) {
        setConnForm({
          source: edge.source,
          target: edge.target,
          protocol: edge.protocol || 'TCP',
          allowed: edge.allowed !== undefined ? edge.allowed : true,
          policy_status: edge.policy_status || (edge.allowed ? 'allowed' : 'denied'),
          business_critical: !!edge.business_critical,
          disruption_cost: edge.disruption_cost !== undefined ? edge.disruption_cost : 1.0,
          port: edge.port ? String(edge.port) : '',
        })
        setIsEditing(false)
        setIsCreatingDevice(false)
        setIsCreatingConn(false)
        setFormError('')
      }
    }
  }, [selectedEdge, network])


  const selectedNode = selectedNodeId ? network?.nodes?.find((n) => n.id === selectedNodeId) : null
  const selectedConnection = selectedEdge
    ? network?.edges?.find((e) => e.source === selectedEdge.source && e.target === selectedEdge.target)
    : null

  // Inbound & outbound connections for selected device
  const deviceConnections = selectedNodeId
    ? {
        outbound: (network?.edges || []).filter((e) => e.source === selectedNodeId),
        inbound: (network?.edges || []).filter((e) => e.target === selectedNodeId),
      }
    : { outbound: [], inbound: [] }

  // -------------------------------------------------------------------------
  // Handlers
  // -------------------------------------------------------------------------
  const handleDeviceSave = async (e) => {
    e.preventDefault()
    setFormError('')
    if (!devForm.name.trim()) {
      setFormError('Device name is required.')
      return
    }

    const ips = devForm.ip_addresses_str
      ? devForm.ip_addresses_str.split(',').map((s) => s.trim()).filter(Boolean)
      : []

    if (isEditing && selectedNodeId) {
      try {
        await onUpdateDevice(selectedNodeId, {
          name: devForm.name.trim(),
          type: devForm.type,
          criticality: Number(devForm.criticality),
          zone: devForm.zone.trim(),
          inferred_role: devForm.inferred_role.trim() || null,
          manual_override: devForm.manual_override,
          hostname: devForm.hostname.trim() || null,
          ip_addresses: ips,
          services: devForm.services || [],
          vulnerabilities: devForm.vulnerabilities || [],
        })
        setIsEditing(false)
      } catch (err) {
        setFormError(err.message)
      }
    } else if (isCreatingDevice) {
      let genId = devForm.id.trim()
      if (!genId) {
        const prefix = devForm.type || 'device'
        let counter = (network?.nodes?.length || 0) + 1
        genId = `${prefix}_${counter}`
        while (network?.nodes?.some((n) => n.id === genId)) {
          counter++
          genId = `${prefix}_${counter}`
        }
      }
      try {
        await onAddDevice({
          id: genId,
          name: devForm.name.trim(),
          type: devForm.type,
          criticality: Number(devForm.criticality),
          zone: devForm.zone.trim(),
          inferred_role: devForm.inferred_role.trim() || null,
          manual_override: devForm.manual_override,
          hostname: devForm.hostname.trim() || null,
          discovery_source: 'manual',
          ip_addresses: ips,
          services: devForm.services || [],
          vulnerabilities: devForm.vulnerabilities || [],
        })
        setIsCreatingDevice(false)
      } catch (err) {
        setFormError(err.message)
      }
    }
  }

  const handleConnectionSave = async (e) => {
    e.preventDefault()
    setFormError('')
    if (!connForm.source || !connForm.target) {
      setFormError('Source and target devices are required.')
      return
    }
    if (connForm.source === connForm.target) {
      setFormError('Self-loop connections are not supported.')
      return
    }

    const portNum = connForm.port ? parseInt(connForm.port, 10) : undefined

    if (isEditing && selectedEdge) {
      try {
        await onUpdateConnection(connForm.source, connForm.target, {
          protocol: connForm.protocol,
          allowed: connForm.policy_status === 'allowed',
          policy_status: connForm.policy_status,
          business_critical: connForm.business_critical,
          disruption_cost: Number(connForm.disruption_cost),
          port: portNum,
        })
        setIsEditing(false)
      } catch (err) {
        setFormError(err.message)
      }
    } else if (isCreatingConn) {
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
        setIsCreatingConn(false)
      } catch (err) {
        setFormError(err.message)
      }
    }
  }

  const handleAddServiceSubmit = async () => {
    if (!newService.name.trim() || !newService.port) return
    const port = parseInt(newService.port, 10)
    if (isNaN(port) || port < 1 || port > 65535) return

    const item = {
      name: newService.name.trim().toLowerCase(),
      port,
      protocol: newService.protocol || 'TCP',
      version: newService.version.trim() || null,
      status: 'active',
    }
    const updatedServices = [...(devForm.services || []), item]
    setDevForm({ ...devForm, services: updatedServices })
    setNewService({ name: '', port: '', protocol: 'TCP', version: '' })
    setShowAddService(false)

    if (selectedNodeId) {
      try {
        await onUpdateDevice(selectedNodeId, { services: updatedServices })
      } catch (err) {
        setFormError(err.message)
      }
    }
  }

  const handleDeleteService = async (idx) => {
    const updatedServices = (devForm.services || []).filter((_, i) => i !== idx)
    setDevForm({ ...devForm, services: updatedServices })
    if (selectedNodeId) {
      try {
        await onUpdateDevice(selectedNodeId, { services: updatedServices })
      } catch (err) {
        setFormError(err.message)
      }
    }
  }

  const handleAddVulnSubmit = async () => {
    if (!newVuln.id.trim() || !newVuln.title.trim()) return
    const portNum = newVuln.service_port ? parseInt(newVuln.service_port, 10) : null
    const cvss = newVuln.cvss_score ? parseFloat(newVuln.cvss_score) : null

    const item = {
      id: newVuln.id.trim().toUpperCase(),
      title: newVuln.title.trim(),
      severity: newVuln.severity,
      cvss_score: cvss,
      service_port: portNum,
      exploit_available: newVuln.exploit_available,
      confidence: newVuln.confidence || 'confirmed',
      evidence: newVuln.evidence.trim() || 'Manual finding registration',
      cwe: newVuln.cwe.trim() || null,
    }
    const updatedVulns = [...(devForm.vulnerabilities || []), item]
    setDevForm({ ...devForm, vulnerabilities: updatedVulns })
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
    setShowAddVuln(false)

    if (selectedNodeId) {
      try {
        await onUpdateDevice(selectedNodeId, { vulnerabilities: updatedVulns })
      } catch (err) {
        setFormError(err.message)
      }
    }
  }

  const handleDeleteVuln = async (idx) => {
    const updatedVulns = (devForm.vulnerabilities || []).filter((_, i) => i !== idx)
    setDevForm({ ...devForm, vulnerabilities: updatedVulns })
    if (selectedNodeId) {
      try {
        await onUpdateDevice(selectedNodeId, { vulnerabilities: updatedVulns })
      } catch (err) {
        setFormError(err.message)
      }
    }
  }

  // -------------------------------------------------------------------------
  // RENDER: Form Mode (Creating or Editing Device/Connection)
  // -------------------------------------------------------------------------
  if (isCreatingDevice || (isEditing && selectedNodeId)) {
    return (
      <div className="flex h-full flex-col select-none bg-s1">
        <div className="flex h-11 items-center justify-between border-b border-line px-4">
          <div className="flex items-center gap-2">
            <span className="eyebrow">{isCreatingDevice ? 'New Device' : 'Edit Device'}</span>
            {!isCreatingDevice && <span className="mono text-fg-subtle">{selectedNodeId}</span>}
          </div>
          <button
            type="button"
            onClick={() => {
              setIsEditing(false)
              setIsCreatingDevice(false)
              setFormError('')
            }}
            className="btn btn-ghost btn-icon"
            title="Cancel"
          >
            <Icon name="x" />
          </button>
        </div>

        <form onSubmit={handleDeviceSave} className="flex-1 overflow-y-auto p-4 space-y-3.5">
          {formError && (
            <div className="rounded border border-danger/40 bg-danger/10 p-2 text-xs text-danger">{formError}</div>
          )}

          <Field label="Device Name *">
            <input
              type="text"
              value={devForm.name}
              onChange={(e) => setDevForm({ ...devForm, name: e.target.value })}
              placeholder="e.g. Core App Server"
              required
              className="input"
            />
          </Field>

          <div className="grid grid-cols-2 gap-2.5">
            <Field label="Device Category">
              <select
                value={devForm.type}
                onChange={(e) => setDevForm({ ...devForm, type: e.target.value })}
                className="input"
              >
                {MAJOR_DEVICE_CATEGORIES.map((c) => (
                  <option key={c.value} value={c.value} className="bg-s2">
                    {c.label}
                  </option>
                ))}
              </select>
            </Field>

            <Field label="Criticality (1-5)">
              <select
                value={devForm.criticality}
                onChange={(e) =>
                  setDevForm({ ...devForm, criticality: Number(e.target.value), manual_override: true })
                }
                className="input mono"
              >
                {[1, 2, 3, 4, 5].map((c) => (
                  <option key={c} value={c} className="bg-s2">
                    C{c} {c >= 4 ? '— High Value' : ''}
                  </option>
                ))}
              </select>
            </Field>
          </div>

          <div className="grid grid-cols-2 gap-2.5">
            <Field label="Security Zone">
              <input
                type="text"
                list="zones-list"
                value={devForm.zone}
                onChange={(e) => setDevForm({ ...devForm, zone: e.target.value })}
                placeholder="e.g. internal, dmz"
                className="input"
              />
              <datalist id="zones-list">
                {ZONES.map((z) => (
                  <option key={z} value={z} />
                ))}
              </datalist>
            </Field>

            <Field label="Inferred Role">
              <input
                type="text"
                value={devForm.inferred_role}
                onChange={(e) => setDevForm({ ...devForm, inferred_role: e.target.value })}
                placeholder="e.g. SQL Database"
                className="input"
              />
            </Field>
          </div>

          <div className="grid grid-cols-2 gap-2.5">
            <Field label="Hostname / FQDN">
              <input
                type="text"
                value={devForm.hostname}
                onChange={(e) => setDevForm({ ...devForm, hostname: e.target.value })}
                placeholder="e.g. db1.internal"
                className="input"
              />
            </Field>

            <Field label="IP Address(es)">
              <input
                type="text"
                value={devForm.ip_addresses_str}
                onChange={(e) => setDevForm({ ...devForm, ip_addresses_str: e.target.value })}
                placeholder="e.g. 192.168.1.10"
                className="input mono"
              />
            </Field>
          </div>

          {isCreatingDevice && (
            <Field label="Device ID (optional)">
              <input
                type="text"
                value={devForm.id}
                onChange={(e) => setDevForm({ ...devForm, id: e.target.value })}
                placeholder="Auto-generated if empty"
                className="input mono"
              />
            </Field>
          )}

          <div className="pt-1">
            <label className="flex items-center gap-2 text-xs text-fg-muted cursor-pointer">
              <input
                type="checkbox"
                checked={devForm.manual_override}
                onChange={(e) => setDevForm({ ...devForm, manual_override: e.target.checked })}
                className="accent-accent"
              />
              <span>Lock Manual Criticality (prevent automatic recommendation override)</span>
            </label>
          </div>

          <div className="flex gap-2 pt-3 border-t border-line">
            <button
              type="button"
              onClick={() => {
                setIsEditing(false)
                setIsCreatingDevice(false)
              }}
              className="btn btn-secondary flex-1"
            >
              Cancel
            </button>
            <button type="submit" className="btn btn-primary flex-1">
              {isCreatingDevice ? 'Create Device' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>
    )
  }

  if (isCreatingConn || (isEditing && selectedEdge)) {
    const nodesList = network?.nodes || []
    return (
      <div className="flex h-full flex-col select-none bg-s1">
        <div className="flex h-11 items-center justify-between border-b border-line px-4">
          <span className="eyebrow">{isCreatingConn ? 'New Connection' : 'Edit Connection'}</span>
          <button
            type="button"
            onClick={() => {
              setIsEditing(false)
              setIsCreatingConn(false)
              setFormError('')
            }}
            className="btn btn-ghost btn-icon"
            title="Cancel"
          >
            <Icon name="x" />
          </button>
        </div>

        <form onSubmit={handleConnectionSave} className="flex-1 overflow-y-auto p-4 space-y-3.5">
          {formError && (
            <div className="rounded border border-danger/40 bg-danger/10 p-2 text-xs text-danger">{formError}</div>
          )}

          <div className="grid grid-cols-2 gap-2.5">
            <Field label="Source (Origin)">
              <select
                disabled={!isCreatingConn}
                value={connForm.source}
                onChange={(e) => setConnForm({ ...connForm, source: e.target.value })}
                className="input"
                required
              >
                <option value="">Select source...</option>
                {nodesList.map((n) => (
                  <option key={n.id} value={n.id} className="bg-s2">
                    {n.name} ({n.id})
                  </option>
                ))}
              </select>
            </Field>

            <Field label="Target (Destination)">
              <select
                disabled={!isCreatingConn}
                value={connForm.target}
                onChange={(e) => setConnForm({ ...connForm, target: e.target.value })}
                className="input"
                required
              >
                <option value="">Select target...</option>
                {nodesList.map((n) => (
                  <option key={n.id} value={n.id} className="bg-s2">
                    {n.name} ({n.id})
                  </option>
                ))}
              </select>
            </Field>
          </div>

          <div className="grid grid-cols-2 gap-2.5">
            <Field label="Protocol">
              <input
                type="text"
                list="proto-list-edit"
                value={connForm.protocol}
                onChange={(e) => setConnForm({ ...connForm, protocol: e.target.value })}
                className="input mono"
                required
              />
              <datalist id="proto-list-edit">
                {PROTOCOLS.map((p) => (
                  <option key={p} value={p} />
                ))}
              </datalist>
            </Field>

            <Field label="Destination Port (optional)">
              <input
                type="number"
                min="1"
                max="65535"
                value={connForm.port}
                onChange={(e) => setConnForm({ ...connForm, port: e.target.value })}
                placeholder="e.g. 443"
                className="input mono"
              />
            </Field>
          </div>

          <div className="grid grid-cols-2 gap-2.5">
            <Field label="Policy Status">
              <select
                value={connForm.policy_status}
                onChange={(e) =>
                  setConnForm({
                    ...connForm,
                    policy_status: e.target.value,
                    allowed: e.target.value === 'allowed',
                  })
                }
                className="input mono"
              >
                <option value="allowed" className="bg-s2">
                  Allowed (Traversable)
                </option>
                <option value="denied" className="bg-s2">
                  Denied (Blocked)
                </option>
                <option value="unknown" className="bg-s2">
                  Unknown (Policy Unconfirmed)
                </option>
              </select>
            </Field>

            <Field label="Disruption Cost">
              <input
                type="number"
                step="0.5"
                min="0"
                value={connForm.disruption_cost}
                onChange={(e) => setConnForm({ ...connForm, disruption_cost: Number(e.target.value) })}
                className="input mono"
              />
            </Field>
          </div>

          <div className="pt-1">
            <label className="flex items-center gap-2 text-xs text-fg-muted cursor-pointer">
              <input
                type="checkbox"
                checked={connForm.business_critical}
                onChange={(e) => setConnForm({ ...connForm, business_critical: e.target.checked })}
                className="accent-accent"
              />
              <span>Business-Critical Link (higher containment penalty)</span>
            </label>
          </div>

          <div className="flex gap-2 pt-3 border-t border-line">
            <button
              type="button"
              onClick={() => {
                setIsEditing(false)
                setIsCreatingConn(false)
              }}
              className="btn btn-secondary flex-1"
            >
              Cancel
            </button>
            <button type="submit" className="btn btn-primary flex-1">
              {isCreatingConn ? 'Add Connection' : 'Save Connection'}
            </button>
          </div>
        </form>
      </div>
    )
  }

  // -------------------------------------------------------------------------
  // RENDER: Selected Device Inspector (Read-Only with Tabs & Action Bar)
  // -------------------------------------------------------------------------
  if (selectedNode) {
    const isCompromised = compromisedId === selectedNode.id
    const deviceTypeLabel =
      MAJOR_DEVICE_CATEGORIES.find((c) => c.value === selectedNode.type)?.label.split(' ')[0] || selectedNode.type

    return (
      <div className="flex h-full flex-col select-none bg-s1">
        {/* Device Inspector Header */}
        <div className="flex items-start justify-between border-b border-line p-4">
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-line bg-s2 p-1.5">
              <img
                src={TYPE_IMAGE[selectedNode.type] || '/unknown.svg'}
                alt=""
                className="h-7 w-7 object-contain"
              />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <h3 className="truncate text-sm font-semibold text-fg" title={selectedNode.name}>
                  {selectedNode.name}
                </h3>
                <CritBadge value={selectedNode.criticality} />
              </div>
              <div className="flex items-center gap-2 text-[11px] text-fg-subtle">
                <span className="mono">{selectedNode.id}</span>
                <span>·</span>
                <span className="capitalize">{deviceTypeLabel}</span>
                {selectedNode.manual_override && <span title="Manual criticality lock">🔒</span>}
              </div>
            </div>
          </div>
          <button type="button" onClick={onClose} className="btn btn-ghost btn-icon" title="Deselect">
            <Icon name="x" />
          </button>
        </div>

        {/* Quick Actions Row */}
        <div className="flex items-center gap-1.5 border-b border-line px-4 py-2 bg-s2/40">
          <button
            type="button"
            onClick={() => onSetCompromised(selectedNode.id)}
            className={`btn text-xs flex-1 ${
              isCompromised
                ? 'border border-danger/40 bg-danger/15 text-danger'
                : 'btn-secondary text-fg-muted hover:text-danger'
            }`}
          >
            <Icon name="alert" size={12} />
            {isCompromised ? 'Compromised (Patient Zero)' : 'Set as Patient Zero'}
          </button>
          <button
            type="button"
            onClick={() => setIsEditing(true)}
            className="btn btn-secondary"
            title="Edit device configuration"
          >
            <Icon name="edit" size={12} />
            Edit
          </button>
          <button
            type="button"
            onClick={() => {
              if (window.confirm(`Delete device '${selectedNode.name}' (${selectedNode.id})?`)) {
                onDeleteDevice(selectedNode.id)
                onClose?.()
              }
            }}
            className="btn btn-danger btn-icon"
            title="Delete device"
          >
            <Icon name="trash" size={12} />
          </button>
        </div>

        {/* Tab Navigation */}
        <Tabs
          tabs={[
            { id: 'overview', label: 'Overview' },
            { id: 'services', label: 'Services', count: selectedNode.services?.length || 0 },
            { id: 'vulns', label: 'Vulnerabilities', count: selectedNode.vulnerabilities?.length || 0 },
            {
              id: 'links',
              label: 'Links',
              count: deviceConnections.outbound.length + deviceConnections.inbound.length,
            },
          ]}
          value={deviceTab}
          onChange={setDeviceTab}
        />

        {/* Tab Content */}
        <div className="flex-1 overflow-y-auto p-4 text-xs">
          {/* TAB 1: OVERVIEW */}
          {deviceTab === 'overview' && (
            <div className="space-y-3.5">
              <div className="space-y-1 rounded-md border border-line bg-s2/60 p-3">
                <KV label="Device Name">{selectedNode.name}</KV>
                <KV label="ID"><span className="mono">{selectedNode.id}</span></KV>
                <KV label="Category"><span className="capitalize">{deviceTypeLabel}</span></KV>
                <KV label="Security Zone">
                  <span className="badge badge-neutral capitalize">{selectedNode.zone || 'internal'}</span>
                </KV>
                <KV label="Inferred Role">{selectedNode.inferred_role}</KV>
                <KV label="Hostname">{selectedNode.hostname ? <span className="mono">{selectedNode.hostname}</span> : null}</KV>
                <KV label="IP Address">{selectedNode.ip_addresses?.length ? <span className="mono">{selectedNode.ip_addresses.join(', ')}</span> : null}</KV>
                <KV label="Discovery Source">{selectedNode.discovery_source || 'manual'}</KV>
              </div>

              {/* Automatic Criticality Recommendation Card */}
              {recommendation && (
                <div className="rounded-md border border-line bg-s2/40 p-3 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="eyebrow text-fg">Criticality Recommendation</span>
                    <span className="badge badge-neutral capitalize">{recommendation.confidence} confidence</span>
                  </div>
                  <div className="flex items-baseline gap-2">
                    <CritBadge value={recommendation.recommended_criticality} />
                    <span className="text-fg-subtle text-[11px]">
                      {selectedNode.manual_override ? '(Overridden manually)' : '(Active)'}
                    </span>
                  </div>
                  <p className="text-[11px] text-fg-muted leading-relaxed">{recommendation.explanation}</p>
                  {recommendation.missing_information?.length > 0 && (
                    <div className="pt-1 text-[11px] text-fg-subtle border-t border-line">
                      <span className="text-warn font-medium">Missing evidence: </span>
                      {recommendation.missing_information.join(' ')}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: SERVICES */}
          {deviceTab === 'services' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-fg-subtle font-medium">Listening Services</span>
                <button
                  type="button"
                  onClick={() => setShowAddService(!showAddService)}
                  className="btn btn-secondary text-xs"
                >
                  <Icon name={showAddService ? 'x' : 'plus'} size={11} />
                  {showAddService ? 'Close' : 'Add Service'}
                </button>
              </div>

              {/* Add Service Inline Form */}
              {showAddService && (
                <div className="rounded-md border border-line bg-s2 p-3 space-y-2">
                  <div className="text-[11px] font-semibold text-fg">Register Service on this Device</div>
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="text"
                      placeholder="Service name (e.g. https)"
                      value={newService.name}
                      onChange={(e) => setNewService({ ...newService, name: e.target.value })}
                      className="input"
                    />
                    <input
                      type="number"
                      placeholder="Port (e.g. 443)"
                      value={newService.port}
                      onChange={(e) => setNewService({ ...newService, port: e.target.value })}
                      className="input mono"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="text"
                      placeholder="Version / Banner (optional)"
                      value={newService.version}
                      onChange={(e) => setNewService({ ...newService, version: e.target.value })}
                      className="input"
                    />
                    <select
                      value={newService.protocol}
                      onChange={(e) => setNewService({ ...newService, protocol: e.target.value })}
                      className="input mono"
                    >
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                    </select>
                  </div>
                  <div className="flex justify-end gap-2 pt-1">
                    <button
                      type="button"
                      onClick={() => setShowAddService(false)}
                      className="btn btn-ghost"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      onClick={handleAddServiceSubmit}
                      className="btn btn-primary"
                    >
                      Save Service
                    </button>
                  </div>
                </div>
              )}

              {/* Service List */}
              {(!selectedNode.services || selectedNode.services.length === 0) ? (
                <Empty>No services configured on this device.</Empty>
              ) : (
                <div className="space-y-1.5">
                  {selectedNode.services.map((s, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between rounded-md border border-line bg-s2/60 px-3 py-2"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-fg">{s.name}</span>
                          <span className="mono text-fg-subtle">
                            :{s.port}/{s.protocol}
                          </span>
                        </div>
                        {s.version && <div className="text-[11px] text-fg-subtle">{s.version}</div>}
                      </div>
                      <button
                        type="button"
                        onClick={() => handleDeleteService(idx)}
                        className="btn btn-ghost btn-icon text-fg-subtle hover:text-danger"
                        title="Remove service"
                      >
                        <Icon name="trash" size={12} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: VULNERABILITIES */}
          {deviceTab === 'vulns' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-fg-subtle font-medium">Vulnerability Findings</span>
                <button
                  type="button"
                  onClick={() => setShowAddVuln(!showAddVuln)}
                  className="btn btn-secondary text-xs"
                >
                  <Icon name={showAddVuln ? 'x' : 'plus'} size={11} />
                  {showAddVuln ? 'Close' : 'Add Finding'}
                </button>
              </div>

              {/* Add Vuln Inline Form */}
              {showAddVuln && (
                <div className="rounded-md border border-line bg-s2 p-3 space-y-2">
                  <div className="text-[11px] font-semibold text-fg">Record Vulnerability Finding</div>
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="text"
                      placeholder="CVE ID (e.g. CVE-2023-38606)"
                      value={newVuln.id}
                      onChange={(e) => setNewVuln({ ...newVuln, id: e.target.value })}
                      className="input mono"
                    />
                    <select
                      value={newVuln.severity}
                      onChange={(e) => setNewVuln({ ...newVuln, severity: e.target.value })}
                      className="input"
                    >
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="number"
                      step="0.1"
                      min="0"
                      max="10"
                      placeholder="CVSS score (0.0-10.0)"
                      value={newVuln.cvss_score}
                      onChange={(e) => setNewVuln({ ...newVuln, cvss_score: e.target.value })}
                      className="input mono"
                    />
                    <input
                      type="number"
                      placeholder="Service Port (optional)"
                      value={newVuln.service_port}
                      onChange={(e) => setNewVuln({ ...newVuln, service_port: e.target.value })}
                      className="input mono"
                    />
                  </div>
                  <input
                    type="text"
                    placeholder="Vulnerability Title / Short summary"
                    value={newVuln.title}
                    onChange={(e) => setNewVuln({ ...newVuln, title: e.target.value })}
                    className="input"
                  />
                  <input
                    type="text"
                    placeholder="Evidence (e.g. banner match, scanner report)"
                    value={newVuln.evidence}
                    onChange={(e) => setNewVuln({ ...newVuln, evidence: e.target.value })}
                    className="input"
                  />
                  <label className="flex items-center gap-2 text-xs text-fg-muted cursor-pointer pt-0.5">
                    <input
                      type="checkbox"
                      checked={newVuln.exploit_available}
                      onChange={(e) => setNewVuln({ ...newVuln, exploit_available: e.target.checked })}
                      className="accent-danger"
                    />
                    <span>Verified public or working exploit available</span>
                  </label>
                  <div className="flex justify-end gap-2 pt-1">
                    <button
                      type="button"
                      onClick={() => setShowAddVuln(false)}
                      className="btn btn-ghost"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      onClick={handleAddVulnSubmit}
                      className="btn btn-primary"
                    >
                      Save Finding
                    </button>
                  </div>
                </div>
              )}

              {/* Vuln List */}
              {(!selectedNode.vulnerabilities || selectedNode.vulnerabilities.length === 0) ? (
                <Empty>No vulnerability findings recorded for this device.</Empty>
              ) : (
                <div className="space-y-2">
                  {selectedNode.vulnerabilities.map((v, idx) => (
                    <div
                      key={idx}
                      className="rounded-md border border-line bg-s2/60 p-2.5 space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="mono font-semibold text-fg">{v.id}</span>
                          <SeverityBadge severity={v.severity} cvss={v.cvss_score} />
                          {v.exploit_available && (
                            <span className="badge badge-danger">exploit available</span>
                          )}
                        </div>
                        <button
                          type="button"
                          onClick={() => handleDeleteVuln(idx)}
                          className="btn btn-ghost btn-icon text-fg-subtle hover:text-danger"
                          title="Remove finding"
                        >
                          <Icon name="trash" size={12} />
                        </button>
                      </div>
                      <div className="text-fg-muted font-medium">{v.title}</div>
                      {v.evidence && (
                        <div className="text-[11px] text-fg-subtle italic">Evidence: {v.evidence}</div>
                      )}
                      {v.service_port && (
                        <div className="mono text-[10px] text-fg-subtle">Associated Port: {v.service_port}</div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 4: CONNECTIONS */}
          {deviceTab === 'links' && (
            <div className="space-y-4">
              <div>
                <div className="eyebrow mb-1.5">Outbound Connections ({deviceConnections.outbound.length})</div>
                {deviceConnections.outbound.length === 0 ? (
                  <Empty>No outbound connections.</Empty>
                ) : (
                  <div className="space-y-1">
                    {deviceConnections.outbound.map((e, idx) => (
                      <div
                        key={idx}
                        onClick={() => onSelectEdge?.(e.source, e.target)}
                        className="row flex items-center justify-between text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span className="text-fg-subtle">→</span>
                          <span className="font-medium text-fg">{e.target}</span>
                          <span className="mono text-fg-subtle">{e.protocol}{e.port ? `:${e.port}` : ''}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <PolicyBadge status={e.policy_status} allowed={e.allowed} />
                          <ObservedBadge observed={e.observed} />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="border-t border-line pt-3">
                <div className="eyebrow mb-1.5">Inbound Connections ({deviceConnections.inbound.length})</div>
                {deviceConnections.inbound.length === 0 ? (
                  <Empty>No inbound connections.</Empty>
                ) : (
                  <div className="space-y-1">
                    {deviceConnections.inbound.map((e, idx) => (
                      <div
                        key={idx}
                        onClick={() => onSelectEdge?.(e.source, e.target)}
                        className="row flex items-center justify-between text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span className="text-fg-subtle">←</span>
                          <span className="font-medium text-fg">{e.source}</span>
                          <span className="mono text-fg-subtle">{e.protocol}{e.port ? `:${e.port}` : ''}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <PolicyBadge status={e.policy_status} allowed={e.allowed} />
                          <ObservedBadge observed={e.observed} />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    )
  }

  // -------------------------------------------------------------------------
  // RENDER: Selected Connection Inspector
  // -------------------------------------------------------------------------
  if (selectedConnection) {
    return (
      <div className="flex h-full flex-col select-none bg-s1">
        <div className="flex h-11 items-center justify-between border-b border-line px-4">
          <div className="flex items-center gap-2 min-w-0">
            <span className="eyebrow">Connection</span>
            <span className="mono text-fg truncate">
              {selectedConnection.source} → {selectedConnection.target}
            </span>
          </div>
          <button type="button" onClick={onClose} className="btn btn-ghost btn-icon" title="Deselect">
            <Icon name="x" />
          </button>
        </div>

        {/* Quick Actions Row */}
        <div className="flex items-center gap-1.5 border-b border-line px-4 py-2 bg-s2/40">
          <button
            type="button"
            onClick={() => setIsEditing(true)}
            className="btn btn-secondary flex-1"
          >
            <Icon name="edit" size={12} />
            Edit Rule
          </button>
          <button
            type="button"
            onClick={() => {
              if (window.confirm(`Delete connection ${selectedConnection.source} → ${selectedConnection.target}?`)) {
                onDeleteConnection(selectedConnection.source, selectedConnection.target)
                onClose?.()
              }
            }}
            className="btn btn-danger btn-icon"
            title="Delete connection"
          >
            <Icon name="trash" size={12} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3.5 text-xs">
          <div className="space-y-1 rounded-md border border-line bg-s2/60 p-3">
            <KV label="Source Device">
              <button
                type="button"
                onClick={() => onSelectNode?.(selectedConnection.source)}
                className="text-accent hover:underline mono font-medium"
              >
                {selectedConnection.source}
              </button>
            </KV>
            <KV label="Target Device">
              <button
                type="button"
                onClick={() => onSelectNode?.(selectedConnection.target)}
                className="text-accent hover:underline mono font-medium"
              >
                {selectedConnection.target}
              </button>
            </KV>
            <KV label="Protocol"><span className="mono">{selectedConnection.protocol}</span></KV>
            <KV label="Target Port">{selectedConnection.port ? <span className="mono">{selectedConnection.port}</span> : <Unknown>Any / unrestricted</Unknown>}</KV>
            <KV label="Policy Status">
              <PolicyBadge status={selectedConnection.policy_status} allowed={selectedConnection.allowed} />
            </KV>
            <KV label="Observed Traffic">
              <ObservedBadge observed={selectedConnection.observed} />
            </KV>
            <KV label="Disruption Cost"><span className="mono">{selectedConnection.disruption_cost ?? 1.0}</span></KV>
            <KV label="Business Critical">
              {selectedConnection.business_critical ? (
                <span className="badge badge-warn">Yes</span>
              ) : (
                <span className="text-fg-subtle">No</span>
              )}
            </KV>
          </div>

          <div className="rounded-md border border-line bg-s2/40 p-3 text-[11px] text-fg-subtle space-y-1">
            <div className="font-semibold text-fg-muted">Traversability in Attack Paths</div>
            <p>
              {selectedConnection.allowed
                ? 'Traffic is permitted by firewall policy. Attack simulations can traverse this link unless blocked by containment actions.'
                : 'Traffic is blocked or unconfirmed. Attack simulations cannot traverse this link without explicit policy authorization.'}
            </p>
          </div>
        </div>
      </div>
    )
  }

  // -------------------------------------------------------------------------
  // RENDER: Default Contextual Ready State (Nothing Selected)
  // -------------------------------------------------------------------------
  return (
    <div className="flex h-full flex-col select-none bg-s1">
      <div className="flex h-11 items-center justify-between border-b border-line px-4">
        <span className="eyebrow">Network Inspector</span>
        <span className="badge badge-neutral">Ready</span>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        <div className="rounded-md border border-line bg-s2/40 p-3.5 space-y-2 text-fg-muted">
          <p className="font-medium text-fg">Topology Inspection & Modification</p>
          <p className="text-[11px] leading-relaxed text-fg-subtle">
            Select any device or connection on the canvas to inspect configured services, vulnerability findings, firewall rules, and traffic observations.
          </p>
        </div>

        <div className="space-y-2">
          <div className="eyebrow">Quick Actions</div>
          <button
            type="button"
            onClick={() => {
              setDevForm({
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
              setIsCreatingDevice(true)
            }}
            className="btn btn-secondary w-full justify-start text-xs"
          >
            <Icon name="plus" size={12} />
            Add Device Manually
          </button>

          <button
            type="button"
            onClick={() => {
              setConnForm({
                source: '',
                target: '',
                protocol: 'HTTPS',
                allowed: true,
                policy_status: 'allowed',
                business_critical: false,
                disruption_cost: 1.0,
                port: '',
              })
              setIsCreatingConn(true)
            }}
            className="btn btn-secondary w-full justify-start text-xs"
          >
            <Icon name="link" size={12} />
            Add Connection Manually
          </button>
        </div>

        <div className="rounded-md border border-line bg-s2/20 p-3 text-[11px] text-fg-subtle space-y-1">
          <span className="font-semibold text-fg-muted">Canvas Shortcuts</span>
          <ul className="list-disc pl-4 space-y-1">
            <li>Drag any device template from the left palette directly onto the canvas.</li>
            <li>Click <strong>Connect</strong> in the top bar, then click any two devices to wire a link.</li>
            <li>Click and drag devices on canvas to customize visual layout.</li>
          </ul>
        </div>
      </div>
    </div>
  )
}
