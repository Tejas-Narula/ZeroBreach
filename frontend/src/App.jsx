import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from './api'
import NetworkGraph, { loadSavedPositions, saveNodePositions } from './components/NetworkGraph'
import ResultsPanel from './components/ResultsPanel'
import ContainmentPanel from './components/ContainmentPanel'
import NetworkEditor from './components/NetworkEditor'
import NodePalette, { currentDraggedTemplate } from './components/NodePalette'
import AnalysisStatsSidebar from './components/AnalysisStatsSidebar'
import ZeekImportModal from './components/ZeekImportModal'

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
    try {
      await api.addDevice(deviceData)
      clearAnalysis()
      await loadNetwork()
      setEditorSelectedNode(deviceData.id)
    } catch (e) {
      throw e
    }
  }

  // Quick auto-add device on clicking empty canvas
  async function handleQuickAddDevice(clickPos) {
    const existing = network?.nodes || []
    const count = existing.length + 1
    const types = ['server', 'database', 'workstation', 'firewall', 'router', 'laptop']
    const zones = ['internal', 'dmz', 'restricted', 'employee']

    const type = types[(count - 1) % types.length]
    const criticality = ((count % 5) || 5)
    const zone = zones[(count - 1) % zones.length]

    let id = `${type}_${count}`
    while (existing.some((n) => n.id === id)) {
      id = `${type}_${Math.floor(Math.random() * 1000)}`
    }

    const name = `${type.charAt(0).toUpperCase() + type.slice(1)} ${count}`

    if (clickPos && typeof clickPos.x === 'number' && typeof clickPos.y === 'number') {
      const posMap = loadSavedPositions()
      posMap[id] = { x: Math.round(clickPos.x), y: Math.round(clickPos.y) }
      saveNodePositions(posMap)
    }

    try {
      await api.addDevice({
        id,
        name,
        type,
        criticality,
        zone,
      })
      clearAnalysis()
      await loadNetwork()
      setPanelMode('editor')
      setEditorSelectedNode(id)
      setEditorSelectedEdge(null)
    } catch (e) {
      setError(e.message)
    }
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
    try {
      await api.updateDevice(deviceId, updates)
      clearAnalysis()
      await loadNetwork()
    } catch (e) {
      throw e
    }
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
    try {
      await api.addConnection(connData)
      clearAnalysis()
      await loadNetwork()
      setEditorSelectedEdge({ source: connData.source, target: connData.target })
    } catch (e) {
      throw e
    }
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
    try {
      await api.updateConnection(source, target, updates)
      clearAnalysis()
      await loadNetwork()
    } catch (e) {
      throw e
    }
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
      setError('Select a valid device to compromise.')
      return
    }
    setLoading(true)
    setError('')
    clearAnalysis()
    try {
      const [analysis, risk, critical, containment, imp] = await Promise.all([
        api.analyze(selected),
        api.risk(selected),
        api.criticalAssets(selected, threshold),
        api.containment(selected, threshold),
        api.impact(selected, threshold),
      ])
      setResults({ analysis, risk, critical, containment })
      setImpact(imp)
      setEnabled(new Set(containment.recommended_actions.map(actionKey)))
      setPanelMode('analysis')
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
    next.has(key) ? next.delete(key) : next.add(key)
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

    // If Connection Mode is active, handle 2-click connection
    if (isConnecting) {
      if (!connectSource) {
        // Step 1: select source node
        setConnectSource(nodeId)
        setError(`Source selected: ${names[nodeId] || nodeId}. Now click the target device.`)
      } else if (connectSource === nodeId) {
        // Clicked same node again: cancel selection
        setConnectSource(null)
        setError('Connection source cancelled.')
      } else {
        // Step 2: click target node -> create connection!
        const src = connectSource
        setConnectSource(null)
        createConnectionBetween(src, nodeId)
        // Keep isConnecting active so user can connect another pair if desired
      }
      return
    }

    // Normal selection
    setEditorSelectedNode(nodeId)
    setEditorSelectedEdge(null)
    setFocus(null)
    if (!results) {
      setSelected(nodeId)
    }
  }

  function onGraphSelectEdge(source, target) {
    if (isConnecting) return
    setEditorSelectedEdge({ source, target })
    setEditorSelectedNode(null)
  }

  function onCanvasClick() {
    if (isConnecting) {
      // Cancel pending connection source on canvas click
      setConnectSource(null)
      setError('')
      return
    }

    // Deselect current selection when clicking empty canvas
    setEditorSelectedNode(null)
    setEditorSelectedEdge(null)
    setFocus(null)
  }

  const graphView = useMemo(() => {
    const v = {
      selected: editorSelectedNode || selected,
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
  }, [editorSelectedNode, selected, focus, results, view, impact, network])

  const totalNodes = network?.nodes?.length || 0
  const totalEdges = network?.edges?.length || 0

  return (
    <div className="flex h-full flex-col">
      {/* HEADER */}
      <header className="flex items-center justify-between border-b border-white/5 bg-[#0b0d10] px-5 py-2.5">
        <div className="flex items-center gap-3">
          <h1 className="text-sm font-semibold tracking-wide text-zinc-100 flex items-center gap-2">
            <span className="inline-block h-2.5 w-2.5 rounded-full bg-emerald-500 animate-pulse" />
            Network Attack Impact Analyzer
          </h1>
          <span className="rounded bg-white/5 px-2 py-0.5 font-mono text-[11px] text-zinc-400">
            {totalNodes} node{totalNodes === 1 ? '' : 's'} · {totalEdges} connection{totalEdges === 1 ? '' : 's'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          {/* Connection Tool Button */}
          <button
            onClick={() => {
              setIsConnecting(!isConnecting)
              setConnectSource(null)
              setError('')
            }}
            className={`rounded px-3 py-1 text-xs font-medium transition flex items-center gap-1.5 ${
              isConnecting
                ? 'bg-emerald-600 text-white shadow-sm ring-2 ring-emerald-400/30'
                : 'bg-white/5 text-zinc-300 hover:bg-white/10'
            }`}
            title="Enable to create directed connections by clicking any 2 nodes"
          >
            <span className={`inline-block h-1.5 w-1.5 rounded-full ${isConnecting ? 'bg-white' : 'bg-emerald-400'}`} />
            {isConnecting ? 'Connect Mode (Active)' : '+ Connect Nodes'}
          </button>

          {/* Panel Mode Switcher Tabs */}
          <div className="flex rounded border border-white/10 bg-white/[0.02] p-0.5 text-xs">
            <button
              onClick={() => setPanelMode('editor')}
              className={`rounded px-3 py-1 font-medium transition ${
                panelMode === 'editor'
                  ? 'bg-sky-600 text-white'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Network Editor
            </button>
            <button
              onClick={() => setPanelMode('analysis')}
              className={`rounded px-3 py-1 font-medium transition ${
                panelMode === 'analysis'
                  ? 'bg-sky-600 text-white'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Attack Analysis {results ? '✓' : ''}
            </button>
          </div>

          <button
            onClick={handleNewNetwork}
            className="rounded bg-white/5 px-2.5 py-1 text-xs text-zinc-300 hover:bg-white/10"
            title="Create an empty network from scratch"
          >
            New Network
          </button>
          <button
            onClick={handleLoadDemoNetwork}
            className="rounded bg-white/5 px-2.5 py-1 text-xs text-zinc-300 hover:bg-white/10"
            title="Load standard 5-device demo topology"
          >
            Load Demo
          </button>
          <button
            onClick={() => setIsImportOpen(true)}
            className="rounded bg-emerald-600/20 border border-emerald-500/30 px-2.5 py-1 text-xs font-medium text-emerald-300 hover:bg-emerald-600/30 transition flex items-center gap-1.5"
            title="Import Zeek conn.log (JSON or TSV) into network"
          >
            <span className="font-mono text-[10px] bg-emerald-500/20 px-1 rounded">ZK</span>
            Import Zeek
          </button>
        </div>
      </header>

      {/* MAIN WORKSPACE */}
      <div className="flex min-h-0 flex-1">
        {/* LEFT SIDEBAR: Device Palette in Editor mode, Analysis Stats in Analysis mode */}
        {panelMode === 'editor' ? (
          <NodePalette />
        ) : (
          <AnalysisStatsSidebar
            results={results}
            impact={impact}
            names={names}
            compromisedId={selected}
          />
        )}

        {/* GRAPH CANVAS */}
        <main className="relative min-w-0 flex-1 bg-[#0b0d10]">
          {/* Connection Mode Banner */}
          {isConnecting && (
            <div className="absolute top-3 left-4 z-10 flex items-center gap-3 rounded-lg border border-emerald-500/40 bg-[#0d1f14]/90 px-3.5 py-2 text-xs text-emerald-200 shadow-lg backdrop-blur">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
              <span>
                {connectSource ? (
                  <>
                    Source: <strong className="text-white underline">{names[connectSource] || connectSource}</strong>. Now click the <strong>Target</strong> device to connect!
                  </>
                ) : (
                  <>Click the <strong>First (Source)</strong> device to begin connection.</>
                )}
              </span>
              <button
                onClick={() => {
                  setIsConnecting(false)
                  setConnectSource(null)
                  setError('')
                }}
                className="ml-2 rounded bg-emerald-500/20 px-2 py-0.5 text-[11px] text-emerald-300 hover:bg-emerald-500/30"
              >
                Done
              </button>
            </div>
          )}

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
                e.stopPropagation()
                e.dataTransfer.dropEffect = 'copy'
              }}
              onDrop={(e) => {
                e.preventDefault()
                e.stopPropagation()
                let template = null
                const jsonStr = e.dataTransfer.getData('application/json') || e.dataTransfer.getData('text/plain')
                if (jsonStr) {
                  try { template = JSON.parse(jsonStr) } catch {}
                }
                if (!template && currentDraggedTemplate) {
                  template = currentDraggedTemplate
                }
                if (template) {
                  handleDropDeviceFromPalette(template, { x: 300, y: 250 })
                }
              }}
              className="flex h-full flex-col items-center justify-center p-6 text-center text-zinc-500 border-2 border-dashed border-white/5 m-4 rounded-xl"
            >
              <div className="rounded-full bg-white/5 p-4 mb-2 text-zinc-400">
                + Drag a device from the left Device Palette and drop it here
              </div>
              <p className="text-sm font-medium text-zinc-400">Empty Network</p>
              <p className="mt-1 max-w-sm text-xs">
                Drag devices from the left palette to start building, or click <button onClick={handleLoadDemoNetwork} className="text-sky-400 underline hover:text-sky-300">Load Demo</button>.
              </p>
            </div>
          )}

          {/* Graph Legend & Status */}
          <div className="pointer-events-none absolute bottom-3 left-4 space-y-1 text-[10px] text-zinc-500">
            <div className="flex gap-4">
              <span><i className="mr-1 inline-block h-2 w-2 bg-[#b23b3b]" />Compromised</span>
              <span><i className="mr-1 inline-block h-2 w-2 bg-[#441c1c] border border-[#da3633]" />Reachable</span>
              <span><i className="mr-1 inline-block h-2 w-2 border-2 border-[#e3b341]" />Critical (C≥4)</span>
              <span><i className="mr-1 inline-block h-0 w-4 border-t-2 border-dashed border-[#2ea043] align-middle" />Contained</span>
              <span><i className="mr-1 inline-block h-0 w-4 border-t-2 border-dashed border-[#484f58] align-middle" />Blocked</span>
            </div>
            <div className="text-zinc-400">
              💡 <span className="font-medium text-zinc-300">Controls:</span> Drag & drop devices from left · Click <strong>+ Connect Nodes</strong> then click any 2 devices · Click device to edit
            </div>
          </div>
        </main>

        {/* RIGHT SIDEBAR */}
        <aside className="flex w-[420px] shrink-0 flex-col overflow-y-auto border-l border-white/5 bg-[#0e1115]">
          {/* EDITOR MODE IN RIGHT SIDEBAR */}
          {panelMode === 'editor' && (
            <div className="flex flex-col h-full">
              <div className="border-b border-white/5 px-4 py-3 bg-white/[0.01] flex items-center justify-between">
                <div>
                  <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                    Network Topology Editor
                  </h2>
                  <p className="text-[11px] text-zinc-500">
                    Build devices and directed communication links
                  </p>
                </div>
                {selected && (
                  <button
                    onClick={runAnalysis}
                    className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 transition shadow-sm"
                  >
                    Analyze Blast Radius →
                  </button>
                )}
              </div>

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
                  setSelected(id)
                  clearAnalysis()
                }}
                compromisedId={selected}
                onClose={() => {
                  setEditorSelectedNode(null)
                  setEditorSelectedEdge(null)
                }}
              />
            </div>
          )}

          {/* ANALYSIS MODE IN RIGHT SIDEBAR */}
          {panelMode === 'analysis' && (
            <div className="flex flex-col h-full">
              {/* Analysis Controls */}
              <div className="space-y-2 border-b border-white/5 px-4 py-3 bg-white/[0.01]">
                <div className="flex gap-2">
                  <select
                    value={selected}
                    onChange={(e) => {
                      setSelected(e.target.value)
                      clearAnalysis()
                    }}
                    disabled={totalNodes === 0}
                    className="flex-1 rounded bg-white/5 px-2 py-1.5 text-xs text-zinc-200 outline-none border border-white/10 disabled:opacity-40"
                  >
                    <option value="">Select compromised device…</option>
                    {network?.nodes?.map((n) => (
                      <option key={n.id} value={n.id} className="bg-zinc-900">
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
                    className="rounded bg-white/5 px-2 py-1.5 text-xs text-zinc-200 outline-none border border-white/10"
                  >
                    {[1, 2, 3, 4, 5].map((t) => (
                      <option key={t} value={t} className="bg-zinc-900">C≥{t}</option>
                    ))}
                  </select>

                  <button
                    onClick={runAnalysis}
                    disabled={loading || !selected || totalNodes === 0}
                    className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-40 transition"
                  >
                    {loading ? 'Analyzing…' : 'Analyze'}
                  </button>
                </div>
                {error && <p className="text-xs text-red-400">{error}</p>}
              </div>

              {!results && !loading && (
                <div className="p-6 text-center text-xs text-zinc-500">
                  {totalNodes === 0 ? (
                    'Network is empty. Use the palette on the left or editor to create devices.'
                  ) : (
                    'Select a compromised entry point above and click Analyze to view reachability, risk scores, and containment options.'
                  )}
                </div>
              )}

              {results && (
                <div className="flex-1 overflow-y-auto">
                  <ResultsPanel
                    analysis={results.analysis}
                    risk={results.risk}
                    critical={results.critical}
                    names={names}
                    focus={focus}
                    setFocus={setFocus}
                  />
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
                </div>
              )}
            </div>
          )}
        </aside>
      </div>

      {/* Zeek Log Ingestion Modal */}
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
