import { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import { IconButton } from './ui'
import { loadSavedPositions, saveNodePositions, TYPE_IMAGE, getDraggedTemplate } from '../utils/graphStorage'

// Palette mirrors CSS tokens in index.css
const C = {
  surface: '#151920',
  line: '#2f3642',
  edge: '#4a5262',
  text: '#c9ced6',
  textMuted: '#8a929e',
  bg: '#0a0c0f',
  accent: '#3b9eff',
  crit: '#e3b341',
  danger: '#f0605a',
  ok: '#3fb67a',
  unknown: '#a78bfa',
}

const style = [
  {
    selector: 'node',
    style: {
      shape: 'round-rectangle',
      width: 46,
      height: 46,
      'background-color': C.surface,
      'background-image': (n) => TYPE_IMAGE[n.data('type')] || '/unknown.svg',
      'background-fit': 'contain',
      'background-clip': 'none',
      'background-width': '70%',
      'background-height': '70%',
      'border-width': 1.5,
      'border-color': C.line,
      label: 'data(label)',
      color: C.text,
      'font-size': 10,
      'font-family': 'Inter, sans-serif',
      'text-wrap': 'wrap',
      'text-max-width': 120,
      'text-valign': 'bottom',
      'text-margin-y': 6,
      'text-background-color': C.bg,
      'text-background-opacity': 0.85,
      'text-background-padding': 2,
      'text-background-shape': 'roundrectangle',
      'min-zoomed-font-size': 6,
      'transition-property': 'opacity, border-color, background-color',
      'transition-duration': 150,
    },
  },
  { selector: 'node[type = "external"]', style: { 'border-style': 'dashed' } },
  { selector: 'node[type = "unknown"]', style: { 'border-style': 'dotted' } },
  { selector: 'node[criticality >= 4]', style: { 'border-color': C.crit, 'border-width': 2.5 } },
  { selector: 'node.reachable', style: { 'background-color': '#3a1d1f', 'border-color': C.danger } },
  {
    selector: 'node.compromised',
    style: {
      'background-color': '#6b1f1f',
      'border-color': C.danger,
      'border-width': 3.5,
      'underlay-color': C.danger,
      'underlay-opacity': 0.25,
      'underlay-padding': 6,
    },
  },
  { selector: 'node.unreached', style: { opacity: 0.55 } },
  {
    selector: 'node.focus',
    style: { 'border-color': C.accent, 'border-width': 3, 'underlay-color': C.accent, 'underlay-opacity': 0.2, 'underlay-padding': 5 },
  },
  {
    selector: 'node.selected',
    style: { 'border-color': C.accent, 'border-width': 3, 'underlay-color': C.accent, 'underlay-opacity': 0.3, 'underlay-padding': 7 },
  },
  {
    selector: 'node.connect-pending-source',
    style: { 'border-color': C.ok, 'border-width': 3.5, 'underlay-color': C.ok, 'underlay-opacity': 0.3, 'underlay-padding': 7 },
  },
  {
    selector: 'edge',
    style: {
      width: 1.75,
      'curve-style': 'bezier',
      'line-color': C.edge,
      'target-arrow-color': C.edge,
      'target-arrow-shape': 'triangle',
      'arrow-scale': 1.1,
      label: 'data(label)',
      'font-size': 8.5,
      'font-family': 'JetBrains Mono, monospace',
      color: C.textMuted,
      'text-background-color': C.bg,
      'text-background-opacity': 0.9,
      'text-background-padding': 1.5,
      'text-rotation': 'autorotate',
      'min-zoomed-font-size': 7,
      'transition-property': 'opacity, line-color',
      'transition-duration': 150,
    },
  },
  {
    selector: ':selected',
    style: {
      'z-index': 999,
    },
  },
  { selector: 'edge.policy-unknown', style: { 'line-style': 'dotted', 'line-color': C.unknown, 'target-arrow-color': C.unknown } },
  {
    selector: 'edge.blocked',
    style: { 'line-style': 'dashed', 'line-dash-pattern': [5, 4], 'line-color': '#363d49', 'target-arrow-color': '#363d49', color: '#555d6a' },
  },
  {
    selector: 'edge.attack',
    style: {
      'line-style': 'dashed',
      'line-dash-pattern': [8, 5],
      'line-color': C.danger,
      'target-arrow-color': C.danger,
      width: 2.75,
    },
  },
  {
    selector: 'edge.sim-blocked',
    style: { 'line-style': 'dashed', 'line-dash-pattern': [5, 4], 'line-color': C.ok, 'target-arrow-color': C.ok, width: 2.5 },
  },
  {
    selector: 'edge.focus',
    style: {
      'line-style': 'dashed',
      'line-dash-pattern': [8, 4],
      width: 3.5,
      'line-color': C.accent,
      'target-arrow-color': C.accent,
      color: C.text,
      'z-index': 10,
    },
  },
  { selector: 'edge.selected', style: { width: 3.5, 'line-color': C.accent, 'target-arrow-color': C.accent, color: C.text } },
  { selector: '.dim', style: { opacity: 0.18 } },
]

function nodeLabel(n) {
  const v = n.vulnerabilities?.length || 0
  const lock = n.manual_override ? ' 🔒' : ''
  return `${n.name}\nC${n.criticality}${v > 0 ? ` · ⚠ ${v}` : ''}${lock}`
}

function edgeLabel(e) {
  return e.port ? `${e.protocol || ''}:${e.port}` : e.protocol || ''
}

function LegendItem({ swatch, label }) {
  return (
    <div className="flex items-center gap-2">
      <span className="flex w-5 justify-center">{swatch}</span>
      <span>{label}</span>
    </div>
  )
}

function Legend({ analysis }) {
  const [open, setOpen] = useState(false)
  const box = (bg, border, extra = '') => (
    <i className={`inline-block h-3 w-3 rounded-sm border-2 ${extra}`} style={{ background: bg, borderColor: border }} />
  )
  const line = (color, styleName = 'solid') => (
    <i className="inline-block w-5" style={{ borderTop: `2px ${styleName} ${color}` }} />
  )
  return (
    <div className="absolute bottom-3 left-3 z-10 rounded-md border border-line bg-s1/95 text-[11px] text-fg-muted shadow-lg backdrop-blur">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex h-7 items-center gap-1.5 px-2.5 font-medium hover:text-fg"
        aria-expanded={open}
      >
        Legend <span className="text-fg-subtle">{open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div className="space-y-1 border-t border-line px-2.5 py-2">
          <LegendItem swatch={box(C.surface, C.crit)} label="Critical asset (C≥4)" />
          <LegendItem swatch={box(C.surface, C.accent)} label="Selected / focused" />
          <LegendItem swatch={line(C.edge)} label="Allowed connection" />
          <LegendItem swatch={line(C.unknown, 'dotted')} label="Policy unknown" />
          <LegendItem swatch={line('#555d6a', 'dashed')} label="Denied by policy" />
          {analysis && (
            <>
              <div className="my-1 h-px bg-line" />
              <LegendItem swatch={box('#6b1f1f', C.danger)} label="Compromised (start)" />
              <LegendItem swatch={box('#3a1d1f', C.danger)} label="Reachable" />
              <LegendItem swatch={line(C.danger)} label="Potential spread" />
              <LegendItem swatch={line(C.ok, 'dashed')} label="Blocked in simulation" />
            </>
          )}
          <div className="pt-1 text-fg-subtle">⚠ n = recorded vulnerabilities · 🔒 = manual criticality</div>
        </div>
      )}
    </div>
  )
}

export default function NetworkGraph({
  network,
  view,
  onSelectNode,
  onSelectEdge,
  onCanvasClick,
  connectSourceId,
  onDropDevice,
}) {
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const viewportRef = useRef(null)
  const handlers = useRef({ onSelectNode, onSelectEdge, onCanvasClick, onDropDevice })
  useEffect(() => {
    handlers.current = { onSelectNode, onSelectEdge, onCanvasClick, onDropDevice }
  }, [onSelectNode, onSelectEdge, onCanvasClick, onDropDevice])

  // Rebuild elements when topology changes
  useEffect(() => {
    if (!network) return
    const savedPositions = loadSavedPositions()
    const currentNodes = network.nodes || []

    const missingNodes = currentNodes.filter((n) => !savedPositions[n.id])
    if (missingNodes.length > 0) {
      const existingEntries = Object.values(savedPositions)
      let baseCenterX = 300
      let baseCenterY = 250
      if (existingEntries.length > 0) {
        baseCenterX = existingEntries.reduce((sum, p) => sum + p.x, 0) / existingEntries.length
        baseCenterY = existingEntries.reduce((sum, p) => sum + p.y, 0) / existingEntries.length
      }
      missingNodes.forEach((node, idx) => {
        const angle = (idx / Math.max(1, missingNodes.length)) * 2 * Math.PI
        const radius = existingEntries.length > 0 ? 160 : 0
        savedPositions[node.id] = {
          x: Math.round(baseCenterX + (radius ? radius * Math.cos(angle) : 0)),
          y: Math.round(baseCenterY + (radius ? radius * Math.sin(angle) : 0)),
        }
      })
      saveNodePositions(savedPositions)
    }

    const elements = [
      ...currentNodes.map((n) => ({
        data: { ...n, label: nodeLabel(n) },
        position: savedPositions[n.id] ? { ...savedPositions[n.id] } : undefined,
      })),
      ...(network.edges || []).map((e) => ({
        data: { ...e, id: `${e.source}->${e.target}`, label: edgeLabel(e) },
      })),
    ]

    // Preserve viewport across rebuilds when the topology is largely the same (e.g. after an edit)
    const prevVp = viewportRef.current
    const sameTopology =
      prevVp && currentNodes.filter((n) => prevVp.ids.has(n.id)).length >= Math.max(1, currentNodes.length / 2)

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style,
      layout: { name: 'preset', padding: 40 },
      minZoom: 0.2,
      maxZoom: 3.0,
      wheelSensitivity: 0.25,
      boxSelectionEnabled: false,
    })

    if (Object.keys(savedPositions).length === 0 && currentNodes.length > 0) {
      cy.layout({ name: 'breadthfirst', directed: true, spacingFactor: 1.3, padding: 40 }).run()
      const newPos = {}
      cy.nodes().forEach((n) => {
        newPos[n.id()] = { ...n.position() }
      })
      saveNodePositions(newPos)
    }
    if (sameTopology) cy.viewport({ zoom: prevVp.zoom, pan: prevVp.pan })
    else if (currentNodes.length > 0) {
      cy.fit(undefined, 50)
      if (cy.zoom() > 1.4) {
        cy.zoom(1.4)
        cy.center()
      }
    }

    cy.on('dragfree', 'node', () => {
      const currentPos = loadSavedPositions()
      cy.nodes().forEach((n) => {
        currentPos[n.id()] = { ...n.position() }
      })
      saveNodePositions(currentPos)
    })
    cy.on('tap', 'node', (e) => handlers.current.onSelectNode?.(e.target.id()))
    cy.on('tap', 'edge', (e) => handlers.current.onSelectEdge?.(e.target.data('source'), e.target.data('target')))
    cy.on('tap', (e) => {
      if (e.target === cy) handlers.current.onCanvasClick?.(e.position)
    })

    cyRef.current = cy
    return () => {
      viewportRef.current = { zoom: cy.zoom(), pan: { ...cy.pan() }, ids: new Set(cy.nodes().map((n) => n.id())) }
      cy.destroy()
    }
  }, [network])

  // Apply state classes
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.batch(() => {
      cy.elements().removeClass(
        'reachable compromised focus selected attack blocked sim-blocked connect-pending-source dim unreached policy-unknown',
      )
      cy.edges().forEach((e) => {
        if (e.data('policy_status') === 'unknown') e.addClass('policy-unknown')
        else if (!e.data('allowed')) e.addClass('blocked')
      })
      const {
        selected, selectedEdge, compromised, reachable = [], blockedEdges = [], focusPath = [], focusEdge, focusNode,
      } = view
      if (selected) cy.getElementById(selected).addClass('selected')
      if (selectedEdge) cy.getElementById(selectedEdge).addClass('selected')

      if (compromised) {
        const reach = new Set(reachable)
        cy.nodes().forEach((n) => {
          if (!reach.has(n.id())) n.addClass('unreached')
        })
        reachable.forEach((id) => cy.getElementById(id).addClass('reachable'))
        cy.getElementById(compromised).removeClass('reachable').addClass('compromised')
        cy.edges().forEach((e) => {
          if (e.data('allowed') && reach.has(e.data('source')) && reach.has(e.data('target'))) e.addClass('attack')
        })
        blockedEdges.forEach((id) => cy.getElementById(id).removeClass('attack').addClass('sim-blocked'))
      }

      // Focus: emphasize the path/element, de-emphasize everything else
      const focused = cy.collection()
      focusPath.forEach((id, i) => {
        focused.merge(cy.getElementById(id))
        if (i > 0) focused.merge(cy.getElementById(`${focusPath[i - 1]}->${id}`))
      })
      if (focusEdge) {
        const edge = cy.getElementById(focusEdge)
        focused.merge(edge).merge(edge.connectedNodes())
      }
      if (focusNode) focused.merge(cy.getElementById(focusNode))
      if (focused.length > 0) {
        focused.addClass('focus')
        cy.elements().not(focused).addClass('dim')
      }

      if (connectSourceId) cy.getElementById(connectSourceId).addClass('connect-pending-source')
    })

    // Animate attack path and focused traversal edges (marching dashes effect)
    let animId = null
    let offset = 0
    const animateEdges = () => {
      offset = (offset - 0.7) % 200
      const activeEdges = cy.edges('.attack, .focus')
      if (activeEdges.length > 0) {
        activeEdges.style('line-dash-offset', offset)
      }
      animId = requestAnimationFrame(animateEdges)
    }

    if (view.compromised || view.focusPath?.length || view.focusEdge) {
      animId = requestAnimationFrame(animateEdges)
    }

    return () => {
      if (animId) cancelAnimationFrame(animId)
    }
  }, [view, network, connectSourceId])

  // Viewport controls
  const zoomBy = (factor) => {
    const cy = cyRef.current
    if (!cy) return
    cy.animate({
      zoom: { level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } },
      duration: 150,
    })
  }
  const fit = () => cyRef.current?.animate({ fit: { padding: 50 }, duration: 200 })
  const centerSelection = () => {
    const cy = cyRef.current
    if (!cy) return
    const targets = cy.$('.focus, .selected')
    if (targets.length) cy.animate({ center: { eles: targets }, duration: 200 })
  }
  const hasSelection = !!(view.selected || view.selectedEdge || view.focusPath?.length || view.focusNode || view.focusEdge)

  // Drag-and-drop from palette
  const handleDragOver = (e) => {
    e.preventDefault()
    e.stopPropagation()
    e.dataTransfer.dropEffect = 'copy'
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    let template = null
    const jsonStr = e.dataTransfer.getData('application/json') || e.dataTransfer.getData('text/plain')
    if (jsonStr) {
      try {
        template = JSON.parse(jsonStr)
      } catch {
        template = null
      }
    }
    if (!template) template = getDraggedTemplate()
    if (!template) return

    const cy = cyRef.current
    let modelPos = null
    if (cy && containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect()
      const pan = cy.pan()
      const zoom = cy.zoom()
      modelPos = {
        x: Math.round((e.clientX - rect.left - pan.x) / zoom),
        y: Math.round((e.clientY - rect.top - pan.y) / zoom),
      }
    }
    handlers.current.onDropDevice?.(template, modelPos)
  }

  return (
    <div className="relative h-full w-full">
      <div ref={containerRef} onDragOver={handleDragOver} onDrop={handleDrop} className="h-full w-full" />

      <div className="absolute right-3 top-3 z-10 flex flex-col rounded-md border border-line bg-s1/95 p-0.5 shadow-lg backdrop-blur">
        <IconButton icon="zoomIn" label="Zoom in" onClick={() => zoomBy(1.25)} />
        <IconButton icon="zoomOut" label="Zoom out" onClick={() => zoomBy(0.8)} />
        <IconButton icon="fit" label="Fit network to screen" onClick={fit} />
        <IconButton icon="target" label="Center on selection" onClick={centerSelection} disabled={!hasSelection} />
      </div>

      <Legend analysis={!!view.compromised} />
    </div>
  )
}
