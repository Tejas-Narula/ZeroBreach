import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from './api'
import NetworkGraph from './components/NetworkGraph'
import { loadSavedPositions, saveNodePositions, getDraggedTemplate } from './utils/graphStorage'
import ResultsPanel from './components/ResultsPanel'
import ContainmentPanel from './components/ContainmentPanel'
import NetworkEditor from './components/NetworkEditor'
import NodePalette from './components/NodePalette'
import ZeekImportModal from './components/ZeekImportModal'
import { Icon, IconButton, Metric } from './components/ui'

const actionKey = (a) =>
  a.action_type === 'block_connection' ? `edge:${a.source}->${a.target}` : `iso:${a.target_device}`

function blockedEdgesFor(actions, network) {
  const ids = new Set()
  actions.forEach((a) => {
    if (a.action_type === 'block_connection') ids.add(`${a.source}->${a.target}`)
    else
      network.edges.forEach((e) => {
        if (e.source === a.target_device || e.target === a.target_device) ids.add(`${e.source}->${e.target}`)
      })
  })
  return [...ids]
}

export default function App() {
  const [network, setNetwork] = useState(null)
  const [selected, setSelected] = useState('')
  const [threshold, setThreshold] = useState(4)
  const [results, setResults] = useState(null)
  const [impact, setImpact] = useState(null)
  const [enabled, setEnabled] = useState(new Set())
  const [view, setView] = useState('original')
  const [focus, setFocus] = useState(null)
  const [loading, setLoading] = useState(false)
  const [simulating, setSimulating] = useState(false)
  const [error, setError] = useState('')

  // Right panel mode: 'editor' | 'analysis'
  const [panelMode, setPanelMode] = useState('editor')
  const [editorSelectedNode, setEditorSelectedNode] = useState(null)
  const [editorSelectedEdge, setEditorSelectedEdge] = useState(null)

  // Sidebar collapse states
  const [paletteCollapsed, setPaletteCollapsed] = useState(false)
  const [inspectorCollapsed, setInspectorCollapsed] = useState(false)

  // Connection creation mode: 2-click connection tool
  const [isConnecting, setIsConnecting] = useState(false)
  const [connectSource, setConnectSource] = useState(null)

  // Zeek Log Import modal state
  const [isImportOpen, setIsImportOpen] = useState(false)

  const clearAnalysis = () => {
    setResults(null)
    setImpact(null)
    setFocus(null)
    setView('original')
  }

  const loadNetwork = useCallback(async () => {
    try {
      const data = await api.getNetwork()
      setNetwork(data)
      setError('')
      if (selected && !data.nodes.some((n) => n.id === selected)) {
        setSelected('')
        clearAnalysis()
      }
    } catch (e) {
      setError(e.message)
    }
  }, [selected])

  useEffect(() => {
    loadNetwork()
  }, [loadNetwork])

  const names = useMemo(
    () => Object.fromEntries((network?.nodes || []).map((n) => [n.id, n.name])),
    [network],
  )

  // -------------------------------------------------------------------------
  // Network Lifecycle Operations
  // -------------------------------------------------------------------------
  async function handleNewNetwork() {
    if (network?.nodes?.length > 0) {
      if (!window.confirm('Clear all devices and connections to start an empty network?')) return
    }
    try {
      localStorage.removeItem('naia_node_positions_v1')
      const res = await api.clearNetwork()
      setNetwork(res.network)
      setSelected('')
      setEditorSelectedNode(null)
      setEditorSelectedEdge(null)
      setIsConnecting(false)
      setConnectSource(null)
      clearAnalysis()
      setPanelMode('editor')
      setError('')
    } catch (e) {
      setError(e.message)
    }
  }

  async function handleLoadDemoNetwork() {
    try {
      localStorage.removeItem('naia_node_positions_v1')
      const res = await api.resetNetwork()
      setNetwork(res.network)
      setSelected('laptop_1')
      setEditorSelectedNode(null)
      setEditorSelectedEdge(null)
      setIsConnecting(false)
      setConnectSource(null)
      clearAnalysis()
      setError('')
    } catch (e) {
      setError(e.message)
    }
  }

  // -------------------------------------------------------------------------
  // Device CRUD Operations
  // -------------------------------------------------------------------------
  async function handleAddDevice(deviceData) {
    await api.addDevice(deviceData)
    clearAnalysis()
    await loadNetwork()
    setEditorSelectedNode(deviceData.id)
  }

  // Drag-and-drop device from Left NodePalette
  async function handleDropDeviceFromPalette(template, clickPos) {
    const existing = network?.nodes || []
    const prefix = template.type || 'device'
    let counter = existing.length + 1
    let id = `${prefix}_${counter}`
    while (existing.some((n) => n.id === id)) {
      counter++
      id = `${prefix}_${counter}`
    }

    const name = `${template.name} ${counter}`

    if (clickPos && typeof clickPos.x === 'number' && typeof clickPos.y === 'number') {
      const posMap = loadSavedPositions()
      posMap[id] = { x: Math.round(clickPos.x), y: Math.round(clickPos.y) }
      saveNodePositions(posMap)
    }

    try {
      await api.addDevice({
        id,
        name,
        type: template.type,
        criticality: template.defaultCriticality,
        zone: template.zone,
      })
      clearAnalysis()
      await loadNetwork()
      setEditorSelectedNode(id)
      setEditorSelectedEdge(null)
    } catch (e) {
      setError(e.message)
    }
  }

  async function handleUpdateDevice(deviceId, updates) {
    await api.updateDevice(deviceId, updates)
    clearAnalysis()
    await loadNetwork()
  }

  async function handleDeleteDevice(deviceId) {
    try {
      await api.deleteDevice(deviceId)
      if (selected === deviceId) {
        setSelected('')
      }
      setEditorSelectedNode(null)
      clearAnalysis()
      await loadNetwork()
    } catch (e) {
      setError(e.message)
    }
  }

  // -------------------------------------------------------------------------
  // Connection CRUD Operations
  // -------------------------------------------------------------------------
  async function handleAddConnection(connData) {
    await api.addConnection(connData)
    clearAnalysis()
    await loadNetwork()
    setEditorSelectedEdge({ source: connData.source, target: connData.target })
  }

  async function createConnectionBetween(sourceId, targetId) {
    if (!sourceId || !targetId || sourceId === targetId) return

    const exists = network?.edges?.some((e) => e.source === sourceId && e.target === targetId)
    if (exists) {
      setError(`Connection ${sourceId} → ${targetId} already exists.`)
      setEditorSelectedEdge({ source: sourceId, target: targetId })
      setEditorSelectedNode(null)
      return
    }

    try {
      await api.addConnection({
        source: sourceId,
        target: targetId,
        protocol: 'HTTPS',
        allowed: true,
        business_critical: false,
        disruption_cost: 1.0,
      })
      clearAnalysis()
      await loadNetwork()
      setEditorSelectedEdge({ source: sourceId, target: targetId })
      setEditorSelectedNode(null)
      setError('')
    } catch (e) {
      setError(e.message)
    }
  }

  async function handleUpdateConnection(source, target, updates) {
    await api.updateConnection(source, target, updates)
    clearAnalysis()
    await loadNetwork()
  }

  async function handleDeleteConnection(source, target) {
    try {
      await api.deleteConnection(source, target)
      setEditorSelectedEdge(null)
      clearAnalysis()
      await loadNetwork()
    } catch (e) {
      setError(e.message)
    }
  }

  // -------------------------------------------------------------------------
  // Analysis Operations
  // -------------------------------------------------------------------------
  async function runAnalysis() {
    if (!selected || !names[selected]) {
      setError('Select a valid device as patient zero.')
      return
    }
    setLoading(true)
    setError('')
    clearAnalysis()
    try {
      const [analysis, risk, critical, containment, imp, services, attackPaths] = await Promise.all([
        api.analyze(selected),
        api.risk(selected),
        api.criticalAssets(selected, threshold),
        api.containment(selected, threshold),
        api.impact(selected, threshold),
        api.serviceReachability(selected).catch(() => null),
        api.attackPaths(selected, threshold).catch(() => null),
      ])
      setResults({ analysis, risk, critical, containment, services, attackPaths })
      setImpact(imp)
      setEnabled(new Set(containment.recommended_actions.map(actionKey)))
      setPanelMode('analysis')
      setInspectorCollapsed(false)
      setEditorSelectedNode(null)
      setEditorSelectedEdge(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  async function toggleAction(key) {
    const next = new Set(enabled)
    if (next.has(key)) {
      next.delete(key)
    } else {
      next.add(key)
    }
    setEnabled(next)
    const custom = results.containment.recommended_actions.filter((a) => next.has(actionKey(a)))
    setSimulating(true)
    try {
      setImpact(
        await api.simulate({
          compromised_device: selected,
          critical_threshold: threshold,
          custom_actions: custom,
        }),
      )
      setError('')
    } catch (e) {
      setError(e.message)
    } finally {
      setSimulating(false)
    }
  }

  // -------------------------------------------------------------------------
  // Graph Interaction Handlers
  // -------------------------------------------------------------------------
  function onGraphSelectNode(nodeId) {
    if (!nodeId) {
      setEditorSelectedNode(null)
      return
    }

    if (isConnecting) {
      if (!connectSource) {
        setConnectSource(nodeId)
      } else if (connectSource === nodeId) {
        setConnectSource(null)
      } else {
        const src = connectSource
        setConnectSource(null)
        createConnectionBetween(src, nodeId)
      }
      return
    }

    setEditorSelectedNode(nodeId)
    setEditorSelectedEdge(null)
    setFocus(null)
    setInspectorCollapsed(false)
  }

  function onGraphSelectEdge(source, target) {
    if (isConnecting) return
    setEditorSelectedEdge({ source, target })
    setEditorSelectedNode(null)
    setFocus(null)
    setPanelMode('editor')
    setInspectorCollapsed(false)
  }

  function onCanvasClick() {
    if (isConnecting) {
      setConnectSource(null)
      return
    }
    setEditorSelectedNode(null)
    setEditorSelectedEdge(null)
    setFocus(null)
  }

  const graphView = useMemo(() => {
    const v = {
      selected: editorSelectedNode,
      selectedEdge: editorSelectedEdge ? `${editorSelectedEdge.source}->${editorSelectedEdge.target}` : null,
      focusPath: focus?.path,
      focusEdge: focus?.edge,
      focusNode: focus?.node,
    }
    if (!results) return v
    v.compromised = results.analysis.compromised_device
    if (view === 'contained' && impact && network) {
      v.reachable = impact.remaining_reachable_devices
      v.blockedEdges = blockedEdgesFor(impact.containment_actions_applied || [], network)
    } else {
      v.reachable = results.analysis.reachable_devices
    }
    return v
  }, [editorSelectedNode, editorSelectedEdge, focus, results, view, impact, network])

  const totalNodes = network?.nodes?.length || 0
  const totalEdges = network?.edges?.length || 0

  return (
    <div className="flex h-full flex-col select-none bg-bg text-fg font-sans antialiased">
      {/* ---------------------------------------------------------------------
          A. TOP NAVIGATION
      --------------------------------------------------------------------- */}
      <header className="flex h-12 shrink-0 items-center justify-between border-b border-line bg-s1 px-4">
        {/* Brand & Network Counter */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="flex h-6 w-6 items-center justify-center rounded-md bg-accent/15 text-accent">
              <Icon name="shield" size={14} />
            </span>
            <span className="text-xs font-semibold tracking-wide text-fg">
              Network Attack Impact Analyzer
            </span>
          </div>

          <span className="mono rounded bg-s2 border border-line px-2 py-0.5 text-[11px] text-fg-subtle">
            {totalNodes} node{totalNodes === 1 ? '' : 's'} · {totalEdges} link{totalEdges === 1 ? '' : 's'}
          </span>
        </div>

        {/* Center: Mode Switcher */}
        <div className="seg">
          <button
            type="button"
            onClick={() => {
              setPanelMode('editor')
              setInspectorCollapsed(false)
            }}
            className={`seg-item ${panelMode === 'editor' ? 'seg-item-active' : ''}`}
          >
            Network Editor
          </button>
          <button
            type="button"
            onClick={() => {
              setPanelMode('analysis')
              setInspectorCollapsed(false)
            }}
            className={`seg-item flex items-center gap-1.5 ${
              panelMode === 'analysis' ? 'seg-item-active' : ''
            }`}
          >
            Attack Analysis
            {results && <span className="h-1.5 w-1.5 rounded-full bg-accent" />}
          </button>
        </div>

        {/* Right: Operational Actions */}
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => {
              setIsConnecting(!isConnecting)
              setConnectSource(null)
              setError('')
            }}
            className={`btn text-xs ${
              isConnecting ? 'bg-ok text-white hover:bg-ok' : 'btn-secondary'
            }`}
            title="Toggle connection wiring mode"
          >
            <Icon name="link" size={13} />
            {isConnecting ? 'Connecting...' : 'Connect'}
          </button>

          <button
            type="button"
            onClick={() => setIsImportOpen(true)}
            className="btn btn-secondary text-xs"
            title="Import Zeek conn.log file"
          >
            <Icon name="upload" size={13} />
            Import Zeek
          </button>

          <button
            type="button"
            onClick={handleLoadDemoNetwork}
            className="btn btn-secondary text-xs"
            title="Reset to 5-device demo topology"
          >
            Demo
          </button>

          <button
            type="button"
            onClick={handleNewNetwork}
            className="btn btn-ghost text-xs text-fg-subtle hover:text-danger"
            title="Clear all nodes and start empty network"
          >
            Clear
          </button>
        </div>
      </header>

      {/* ---------------------------------------------------------------------
          MAIN WORKSPACE
      --------------------------------------------------------------------- */}
      <div className="flex min-h-0 flex-1">
        {/* B. LEFT SIDEBAR: Device Palette (in Editor mode) */}
        {panelMode === 'editor' && (
          <NodePalette
            collapsed={paletteCollapsed}
            onToggle={() => setPaletteCollapsed(!paletteCollapsed)}
          />
        )}

        {/* C. CENTRAL WORKSPACE: Network Graph Canvas */}
        <main className="relative min-w-0 flex-1 bg-bg">
          {/* Active Connection Tool Prompt Banner */}
          {isConnecting && (
            <div className="absolute top-3 left-4 z-20 flex items-center gap-3 rounded-md border border-ok/40 bg-s1/95 px-3.5 py-2 text-xs text-fg shadow-xl backdrop-blur">
              <span className="h-2 w-2 rounded-full bg-ok animate-pulse" />
              <span>
                {connectSource ? (
                  <>
                    Source selected: <strong className="text-ok font-semibold">{names[connectSource] || connectSource}</strong>. Now click the target device.
                  </>
                ) : (
                  <>Click the first device (source) to begin wiring a connection.</>
                )}
              </span>
              <button
                type="button"
                onClick={() => {
                  setIsConnecting(false)
                  setConnectSource(null)
                }}
                className="btn btn-secondary h-6 px-2 text-[11px]"
              >
                Done
              </button>
            </div>
          )}

          {/* Graph or Empty State */}
          {totalNodes > 0 ? (
            <NetworkGraph
              network={network}
              view={graphView}
              onSelectNode={onGraphSelectNode}
              onSelectEdge={onGraphSelectEdge}
              onCanvasClick={onCanvasClick}
              connectSourceId={connectSource}
              onDropDevice={handleDropDeviceFromPalette}
            />
          ) : (
            <div
              onDragOver={(e) => {
                e.preventDefault()
                e.dataTransfer.dropEffect = 'copy'
              }}
              onDrop={(e) => {
                e.preventDefault()
                let template = null
                const jsonStr = e.dataTransfer.getData('application/json') || e.dataTransfer.getData('text/plain')
                if (jsonStr) {
                  try {
                    template = JSON.parse(jsonStr)
                  } catch {}
                }
                if (!template) template = getDraggedTemplate()
                if (template) {
                  handleDropDeviceFromPalette(template, { x: 300, y: 250 })
                }
              }}
              className="flex h-full flex-col items-center justify-center p-6 text-center text-fg-subtle border-2 border-dashed border-line m-6 rounded-xl"
            >
              <div className="rounded-full bg-s2 p-4 mb-3 border border-line">
                <Icon name="graph" size={28} className="text-fg-subtle" />
              </div>
              <p className="text-sm font-semibold text-fg">Empty Network Canvas</p>
              <p className="mt-1 max-w-sm text-xs text-fg-subtle">
                Drag devices from the left palette onto the canvas, or click{' '}
                <button
                  type="button"
                  onClick={handleLoadDemoNetwork}
                  className="text-accent underline hover:text-accent-strong"
                >
                  Load Demo Network
                </button>.
              </p>
            </div>
          )}
        </main>

        {/* ---------------------------------------------------------------------
            D. RIGHT SIDEBAR: Contextual Inspector OR Attack Analysis Workspace
        --------------------------------------------------------------------- */}
        {inspectorCollapsed ? (
          <aside className="flex w-10 shrink-0 flex-col items-center border-l border-line bg-s1 py-3">
            <IconButton
              icon="chevronLeft"
              label="Expand panel"
              onClick={() => setInspectorCollapsed(false)}
            />
            <div className="my-2 h-px w-5 bg-line" />
            <span
              className="mono text-[10px] text-fg-subtle rotate-90 whitespace-nowrap mt-4"
              style={{ transformOrigin: 'left top' }}
            >
              {panelMode === 'editor' ? 'INSPECTOR' : 'ANALYSIS'}
            </span>
          </aside>
        ) : (
          <aside className="flex w-[380px] shrink-0 flex-col border-l border-line bg-s1">
            {/* IN NETWORK EDITOR MODE: Contextual Inspector */}
            {panelMode === 'editor' && (
              <NetworkEditor
                network={network}
                selectedNodeId={editorSelectedNode}
                selectedEdge={editorSelectedEdge}
                onAddDevice={handleAddDevice}
                onUpdateDevice={handleUpdateDevice}
                onDeleteDevice={handleDeleteDevice}
                onAddConnection={handleAddConnection}
                onUpdateConnection={handleUpdateConnection}
                onDeleteConnection={handleDeleteConnection}
                onSetCompromised={(id) => {
                  setSelected((prev) => (prev === id ? '' : id))
                  clearAnalysis()
                }}
                compromisedId={selected}
                onClose={() => {
                  setEditorSelectedNode(null)
                  setEditorSelectedEdge(null)
                }}
                onSelectNode={(id) => {
                  setEditorSelectedNode(id)
                  setEditorSelectedEdge(null)
                }}
                onSelectEdge={(s, t) => {
                  setEditorSelectedEdge({ source: s, target: t })
                  setEditorSelectedNode(null)
                }}
              />
            )}

            {/* IN ATTACK ANALYSIS MODE: Focused Analysis Workspace */}
            {panelMode === 'analysis' && (
              <div className="flex flex-col h-full">
                {/* Header & Collapse */}
                <div className="flex h-11 items-center justify-between border-b border-line px-4 bg-s1">
                  <div className="flex items-center gap-2">
                    <span className="eyebrow">Attack Analysis</span>
                    {results && <span className="badge badge-accent">Calculated</span>}
                  </div>
                  <IconButton
                    icon="chevronRight"
                    label="Collapse panel"
                    onClick={() => setInspectorCollapsed(true)}
                  />
                </div>

                {/* 4.A Compact Analysis Toolbar */}
                <div className="border-b border-line p-3 bg-s2/40 space-y-2">
                  <div className="grid grid-cols-[1fr_auto] gap-2">
                    <select
                      value={selected}
                      onChange={(e) => {
                        setSelected(e.target.value)
                        clearAnalysis()
                      }}
                      disabled={totalNodes === 0}
                      className="input"
                    >
                      <option value="">Patient Zero (Compromised)...</option>
                      {network?.nodes?.map((n) => (
                        <option key={n.id} value={n.id} className="bg-s2">
                          {n.name} ({n.id})
                        </option>
                      ))}
                    </select>

                    <select
                      value={threshold}
                      onChange={(e) => {
                        setThreshold(Number(e.target.value))
                        clearAnalysis()
                      }}
                      title="Critical asset threshold"
                      className="input mono w-20"
                    >
                      {[1, 2, 3, 4, 5].map((t) => (
                        <option key={t} value={t} className="bg-s2">
                          C≥{t}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={runAnalysis}
                      disabled={loading || !selected || totalNodes === 0}
                      className="btn btn-primary flex-1"
                    >
                      <Icon name="play" size={12} />
                      {loading ? 'Analyzing Graph...' : 'Analyze Attack Impact'}
                    </button>
                    {results && (
                      <button
                        type="button"
                        onClick={clearAnalysis}
                        className="btn btn-secondary"
                        title="Clear analysis results"
                      >
                        Reset
                      </button>
                    )}
                  </div>

                  {error && (
                    <div className="rounded border border-danger/40 bg-danger/10 p-2 text-xs text-danger">
                      {error}
                    </div>
                  )}
                </div>

                {/* 4.B Summary Metrics Bar */}
                {results && (
                  <div className="grid grid-cols-4 gap-1.5 p-3 border-b border-line bg-s2/20">
                    <Metric
                      label="Exposed"
                      value={results.analysis.reachable_devices.length - 1}
                      hint="Total downstream reachable devices"
                    />
                    <Metric
                      label="Critical"
                      value={results.critical?.count ?? 0}
                      tone={results.critical?.count > 0 ? 'crit' : 'neutral'}
                      hint="Reachable assets meeting criticality threshold"
                    />
                    <Metric
                      label="Paths"
                      value={results.attackPaths?.total_attack_paths ?? 0}
                      tone={results.attackPaths?.total_attack_paths > 0 ? 'danger' : 'neutral'}
                      hint="Discovered multi-hop attack routes"
                    />
                    <Metric
                      label="Vulnerable"
                      value={results.services?.services_with_vulnerabilities ?? 0}
                      tone={results.services?.services_with_vulnerabilities > 0 ? 'warn' : 'neutral'}
                      hint="Exposed services with recorded CVEs"
                    />
                  </div>
                )}

                {/* Main Results Container (Sections 1-4) */}
                <div className="flex-1 overflow-y-auto">
                  {!results && !loading && (
                    <div className="p-6 text-center text-xs text-fg-subtle space-y-2">
                      <Icon name="target" size={24} className="mx-auto text-fg-subtle opacity-60" />
                      <p className="font-medium text-fg-muted">No Analysis Active</p>
                      <p className="text-[11px] leading-relaxed">
                        Select a patient zero device above and click <strong>Analyze Attack Impact</strong> to evaluate blast radius, multi-hop attack paths, and containment options.
                      </p>
                    </div>
                  )}

                  {results && (
                    <>
                      {/* Sections 1, 2, 3: Critical Assets, Attack Paths, Risk Ranking */}
                      <ResultsPanel
                        analysis={results.analysis}
                        risk={results.risk}
                        critical={results.critical}
                        services={results.services}
                        attackPaths={results.attackPaths}
                        names={names}
                        focus={focus}
                        setFocus={setFocus}
                      />

                      {/* Section 4: Recommended Containment & Simulation */}
                      <ContainmentPanel
                        containment={results.containment}
                        impact={impact}
                        enabled={enabled}
                        toggleAction={toggleAction}
                        names={names}
                        focus={focus}
                        setFocus={setFocus}
                        view={view}
                        setView={setView}
                        simulating={simulating}
                      />
                    </>
                  )}
                </div>
              </div>
            )}
          </aside>
        )}
      </div>

      {/* ---------------------------------------------------------------------
          MODALS
      --------------------------------------------------------------------- */}
      <ZeekImportModal
        isOpen={isImportOpen}
        onClose={() => setIsImportOpen(false)}
        onImportSuccess={(res) => {
          localStorage.removeItem('naia_node_positions_v1')
          setNetwork(res.network)
          clearAnalysis()
          if (res.network?.nodes?.length > 0) {
            setSelected(res.network.nodes[0].id)
          } else {
            setSelected('')
          }
          setEditorSelectedNode(null)
          setEditorSelectedEdge(null)
          setError('')
        }}
      />
    </div>
  )
}
