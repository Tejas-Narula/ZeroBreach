import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from './api'
import NetworkGraph from './components/NetworkGraph'
import ResultsPanel from './components/ResultsPanel'
import ContainmentPanel from './components/ContainmentPanel'
import NetworkEditor from './components/NetworkEditor'

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

  // Editor toggle and element selection
  const [showEditor, setShowEditor] = useState(false)
  const [editorSelectedNode, setEditorSelectedNode] = useState(null)
  const [editorSelectedEdge, setEditorSelectedEdge] = useState(null)

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
      // Validate selected compromised device still exists
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
      const res = await api.clearNetwork()
      setNetwork(res.network)
      setSelected('')
      setEditorSelectedNode(null)
      setEditorSelectedEdge(null)
      clearAnalysis()
      setShowEditor(true)
      setError('')
    } catch (e) {
      setError(e.message)
    }
  }

  async function handleLoadDemoNetwork() {
    try {
      const res = await api.resetNetwork()
      setNetwork(res.network)
      setSelected('laptop_1')
      setEditorSelectedNode(null)
      setEditorSelectedEdge(null)
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
    setEditorSelectedNode(nodeId)
    setEditorSelectedEdge(null)
    setFocus(null)
    // If not analyzing yet, also make it the selected target for analysis
    if (!results) {
      setSelected(nodeId)
    }
  }

  function onGraphSelectEdge(source, target) {
    setEditorSelectedEdge({ source, target })
    setEditorSelectedNode(null)
    setShowEditor(true)
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
          <h1 className="text-sm font-semibold tracking-wide text-zinc-100">
            Network Attack Impact Analyzer
          </h1>
          <span className="rounded bg-white/5 px-2 py-0.5 font-mono text-[11px] text-zinc-400">
            {totalNodes} node{totalNodes === 1 ? '' : 's'} · {totalEdges} connection{totalEdges === 1 ? '' : 's'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowEditor(!showEditor)}
            className={`rounded px-2.5 py-1 text-xs font-medium transition ${
              showEditor ? 'bg-sky-600 text-white' : 'bg-white/5 text-zinc-300 hover:bg-white/10'
            }`}
          >
            {showEditor ? 'Hide Editor' : 'Edit Network'}
          </button>
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
        </div>
      </header>

      {/* NETWORK EDITOR PANEL */}
      {showEditor && (
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
          onClose={() => setShowEditor(false)}
        />
      )}

      {/* MAIN CONTENT AREA */}
      <div className="flex min-h-0 flex-1">
        {/* GRAPH VIEW */}
        <main className="relative min-w-0 flex-1">
          {totalNodes > 0 ? (
            <NetworkGraph
              network={network}
              view={graphView}
              onSelectNode={onGraphSelectNode}
              onSelectEdge={onGraphSelectEdge}
            />
          ) : (
            <div className="flex h-full flex-col items-center justify-center p-6 text-center text-zinc-500">
              <p className="text-sm font-medium text-zinc-400">Empty Network</p>
              <p className="mt-1 max-w-sm text-xs">
                No devices found. Use <button onClick={() => setShowEditor(true)} className="text-sky-400 underline hover:text-sky-300">Edit Network</button> to add custom devices and connections, or click <button onClick={handleLoadDemoNetwork} className="text-sky-400 underline hover:text-sky-300">Load Demo</button>.
              </p>
            </div>
          )}

          {/* Graph Legend & Status */}
          <div className="pointer-events-none absolute bottom-3 left-4 space-y-1 text-[10px] text-zinc-500">
            <div className="flex gap-4">
              <span><i className="mr-1 inline-block h-2 w-2 bg-[#b23b3b]" />Compromised</span>
              <span><i className="mr-1 inline-block h-2 w-2 bg-[#4a2a2a]" />Reachable</span>
              <span><i className="mr-1 inline-block h-2 w-2 border-2 border-[#c9a24a]" />Critical (C≥4)</span>
              <span><i className="mr-1 inline-block h-0 w-4 border-t-2 border-dashed border-[#5f8f6a] align-middle" />Contained</span>
              <span><i className="mr-1 inline-block h-0 w-4 border-t-2 border-dashed border-[#4b5363] align-middle" />Blocked</span>
            </div>
            <div>Click a device or connection to edit its properties or inspect attack blast radius</div>
          </div>
        </main>

        {/* RIGHT ANALYSIS SIDEBAR */}
        <aside className="flex w-[400px] shrink-0 flex-col overflow-y-auto border-l border-white/5 bg-[#0e1115]">
          {/* Analysis Controls */}
          <div className="space-y-2 border-b border-white/5 px-4 py-3">
            <div className="flex gap-2">
              <select
                value={selected}
                onChange={(e) => {
                  setSelected(e.target.value)
                  clearAnalysis()
                }}
                disabled={totalNodes === 0}
                className="flex-1 rounded bg-white/5 px-2 py-1.5 text-xs text-zinc-200 outline-none disabled:opacity-40"
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
                className="rounded bg-white/5 px-2 py-1.5 text-xs text-zinc-200 outline-none"
              >
                {[1, 2, 3, 4, 5].map((t) => (
                  <option key={t} value={t} className="bg-zinc-900">C≥{t}</option>
                ))}
              </select>

              <button
                onClick={runAnalysis}
                disabled={loading || !selected || totalNodes === 0}
                className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-40"
              >
                {loading ? 'Analyzing…' : 'Analyze'}
              </button>
            </div>
            {error && <p className="text-xs text-red-400">{error}</p>}
          </div>

          {!results && !loading && (
            <div className="px-4 py-6 text-xs text-zinc-500">
              {totalNodes === 0 ? (
                'Add devices and connections above to begin attack simulation.'
              ) : (
                'Select a compromised device from the list or click a node on the graph, then click Analyze.'
              )}
            </div>
          )}

          {results && (
            <>
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
            </>
          )}
        </aside>
      </div>
    </div>
  )
}
