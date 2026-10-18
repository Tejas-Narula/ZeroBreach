import { useEffect, useRef } from 'react'
import cytoscape from 'cytoscape'
import { currentDraggedTemplate } from './NodePalette'

const STORAGE_KEY = 'naia_node_positions_v1'

export function loadSavedPositions() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) : {}
  } catch {
    return {}
  }
}

export function saveNodePositions(positionsMap) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(positionsMap))
  } catch {
    // ignore storage errors
  }
}

// Map device types to icons from /public
export const TYPE_IMAGE = {
  laptop: '/computer.png',
  workstation: '/computer.png',
  computer: '/computer.png',
  server: '/server.png',
  database: '/server.png',
  router: '/wifi-router.png',
  firewall: '/hub.png',
  hub: '/hub.png',
}

const style = [
  {
    selector: 'node',
    style: {
      shape: 'round-rectangle',
      width: 56,
      height: 56,
      'background-color': '#161b22',
      'background-image': (n) => TYPE_IMAGE[n.data('type')] || '/server.png',
      'background-fit': 'contain',
      'background-clip': 'none',
      'background-image-opacity': 0.95,
      'border-width': 2,
      'border-color': '#30363d',
      label: 'data(label)',
      color: '#c9ced6',
      'font-size': 10,
      'font-family': 'Inter, sans-serif',
      'text-wrap': 'wrap',
      'text-valign': 'bottom',
      'text-margin-y': 7,
      'text-background-color': '#0b0d10',
      'text-background-opacity': 0.85,
      'text-background-padding': 2,
      'text-background-shape': 'roundrectangle',
    },
  },
  {
    selector: 'node[criticality >= 4]',
    style: {
      'border-color': '#d29922',
      'border-width': 3,
    },
  },
  {
    selector: 'node[criticality = 5]',
    style: {
      'border-color': '#e3b341',
      'border-width': 4,
    },
  },
  {
    selector: 'node.reachable',
    style: {
      'background-color': '#441c1c',
      'border-color': '#da3633',
    },
  },
  {
    selector: 'node.compromised',
    style: {
      'background-color': '#b22222',
      'border-color': '#f85149',
      'border-width': 4,
      'overlay-color': '#f85149',
      'overlay-opacity': 0.25,
      'overlay-padding': 6,
    },
  },
  {
    selector: 'node.focus',
    style: {
      'overlay-color': '#58a6ff',
      'overlay-opacity': 0.25,
      'overlay-padding': 6,
    },
  },
  {
    selector: 'node.selected',
    style: {
      'underlay-color': '#58a6ff',
      'underlay-opacity': 0.35,
      'underlay-padding': 8,
      'border-color': '#58a6ff',
    },
  },
  // In connection mode: source node selected
  {
    selector: 'node.connect-pending-source',
    style: {
      'border-color': '#22c55e',
      'border-width': 4,
      'overlay-color': '#22c55e',
      'overlay-opacity': 0.3,
      'overlay-padding': 8,
    },
  },
  {
    selector: 'edge',
    style: {
      width: 2.5,
      'curve-style': 'bezier',
      'line-color': '#484f58',
      'target-arrow-color': '#484f58',
      'target-arrow-shape': 'triangle',
      'arrow-scale': 1.2,
      label: 'data(protocol)',
      'font-size': 9,
      color: '#8b949e',
      'text-background-color': '#0b0d10',
      'text-background-opacity': 0.95,
      'text-background-padding': 2,
    },
  },
  {
    selector: 'edge.attack',
    style: {
      'line-color': '#da3633',
      'target-arrow-color': '#da3633',
      width: 3,
    },
  },
  {
    selector: 'edge.blocked',
    style: {
      'line-style': 'dashed',
      'line-dash-pattern': [6, 4],
      'line-color': '#30363d',
      'target-arrow-color': '#30363d',
      color: '#484f58',
    },
  },
  {
    selector: 'edge.sim-blocked',
    style: {
      'line-style': 'dashed',
      'line-dash-pattern': [6, 4],
      'line-color': '#2ea043',
      'target-arrow-color': '#2ea043',
    },
  },
  {
    selector: 'edge.focus',
    style: {
      width: 4,
      'line-color': '#58a6ff',
      'target-arrow-color': '#58a6ff',
    },
  },
]

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
  const handlers = useRef({ onSelectNode, onSelectEdge, onCanvasClick, onDropDevice })
  handlers.current = { onSelectNode, onSelectEdge, onCanvasClick, onDropDevice }

  // Rebuild elements when topology changes
  useEffect(() => {
    if (!network) return
    const savedPositions = loadSavedPositions()
    const currentNodes = network.nodes || []

    // Ensure all nodes have coordinates
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
        const posX = Math.round(baseCenterX + (radius ? radius * Math.cos(angle) : 0))
        const posY = Math.round(baseCenterY + (radius ? radius * Math.sin(angle) : 0))
        savedPositions[node.id] = { x: posX, y: posY }
      })

      saveNodePositions(savedPositions)
    }

    const elements = [
      ...currentNodes.map((n) => ({
        data: { ...n, label: `${n.name}\n${n.type} · C${n.criticality}` },
        position: savedPositions[n.id] ? { ...savedPositions[n.id] } : undefined,
      })),
      ...(network.edges || []).map((e) => ({
        data: { ...e, id: `${e.source}->${e.target}` },
      })),
    ]

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style,
      layout: { name: 'preset', padding: 35 },
      minZoom: 0.2,
      maxZoom: 3.0,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
    })

    // Center viewport on initial empty launch
    if (Object.keys(savedPositions).length === 0 && currentNodes.length > 0) {
      cy.layout({ name: 'breadthfirst', directed: true, spacingFactor: 1.3, padding: 35 }).run()
      const newPos = {}
      cy.nodes().forEach((n) => {
        newPos[n.id()] = { ...n.position() }
      })
      saveNodePositions(newPos)
    }

    // Persist position when user drags any node
    cy.on('dragfree', 'node', () => {
      const currentPos = loadSavedPositions()
      cy.nodes().forEach((n) => {
        currentPos[n.id()] = { ...n.position() }
      })
      saveNodePositions(currentPos)
    })

    // Click on node
    cy.on('tap', 'node', (e) => {
      handlers.current.onSelectNode?.(e.target.id())
    })

    // Click on edge
    cy.on('tap', 'edge', (e) => {
      handlers.current.onSelectEdge?.(e.target.data('source'), e.target.data('target'))
    })

    // Click on background
    cy.on('tap', (e) => {
      if (e.target === cy) {
        handlers.current.onCanvasClick?.(e.position)
      }
    })

    cyRef.current = cy
    return () => cy.destroy()
  }, [network])

  // Apply highlight classes & pending connection source highlighting
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.batch(() => {
      cy.elements().removeClass(
        'reachable compromised focus selected attack blocked sim-blocked connect-pending-source',
      )
      cy.edges().forEach((e) => {
        if (!e.data('allowed')) e.addClass('blocked')
      })
      const { selected, compromised, reachable = [], blockedEdges = [], focusPath = [], focusEdge, focusNode } = view
      if (selected) cy.getElementById(selected).addClass('selected')
      reachable.forEach((id) => cy.getElementById(id).addClass('reachable'))
      if (compromised) cy.getElementById(compromised).addClass('compromised')
      const reach = new Set(reachable)
      cy.edges().forEach((e) => {
        if (e.data('allowed') && reach.has(e.data('source')) && reach.has(e.data('target'))) e.addClass('attack')
      })
      blockedEdges.forEach((id) => cy.getElementById(id).removeClass('attack').addClass('sim-blocked'))
      focusPath.forEach((id, i) => {
        cy.getElementById(id).addClass('focus')
        if (i > 0) cy.getElementById(`${focusPath[i - 1]}->${id}`).addClass('focus')
      })
      if (focusEdge) cy.getElementById(focusEdge).addClass('focus')
      if (focusNode) cy.getElementById(focusNode).addClass('focus')

      // If in connect mode with source picked
      if (connectSourceId) {
        cy.getElementById(connectSourceId).addClass('connect-pending-source')
      }
    })
  }, [view, network, connectSourceId])

  // -------------------------------------------------------------------------
  // HTML5 Drag-and-Drop Handler: Drop template from palette directly on canvas
  // -------------------------------------------------------------------------
  const handleDragOver = (e) => {
    e.preventDefault()
    e.stopPropagation()
    e.dataTransfer.dropEffect = 'copy'
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()

    let template = null
    const jsonStr =
      e.dataTransfer.getData('application/json') || e.dataTransfer.getData('text/plain')
    if (jsonStr) {
      try {
        template = JSON.parse(jsonStr)
      } catch {
        template = null
      }
    }

    if (!template && currentDraggedTemplate) {
      template = currentDraggedTemplate
    }

    if (template) {
      processDrop(template, e)
    }
  }

  const processDrop = (template, e) => {
    if (!template) return
    const cy = cyRef.current
    let modelPos = null

    if (cy && containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect()
      const renderedPos = {
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
      }
      const pan = cy.pan()
      const zoom = cy.zoom()
      modelPos = {
        x: Math.round((renderedPos.x - pan.x) / zoom),
        y: Math.round((renderedPos.y - pan.y) / zoom),
      }
    }

    handlers.current.onDropDevice?.(template, modelPos)
  }

  return (
    <div
      ref={containerRef}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
      className="h-full w-full relative"
    />
  )
}
