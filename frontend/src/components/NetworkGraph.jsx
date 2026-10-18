import { useEffect, useRef } from 'react'
import cytoscape from 'cytoscape'

const TYPE_SHAPE = {
  laptop: 'round-rectangle',
  workstation: 'round-rectangle',
  server: 'rectangle',
  database: 'barrel',
  firewall: 'diamond',
  router: 'hexagon',
}

const style = [
  {
    selector: 'node',
    style: {
      shape: (n) => TYPE_SHAPE[n.data('type')] || 'ellipse',
      width: 52,
      height: 52,
      'background-color': '#1c2128',
      'border-width': 2,
      'border-color': '#3b4250',
      label: 'data(label)',
      color: '#c9ced6',
      'font-size': 10,
      'font-family': 'Inter, sans-serif',
      'text-wrap': 'wrap',
      'text-valign': 'bottom',
      'text-margin-y': 6,
    },
  },
  { selector: 'node[criticality >= 4]', style: { 'border-color': '#b08a3e', 'border-width': 3 } },
  { selector: 'node[criticality = 5]', style: { 'border-color': '#c9a24a', 'border-width': 4 } },
  { selector: 'node.reachable', style: { 'background-color': '#4a2a2a' } },
  { selector: 'node.compromised', style: { 'background-color': '#b23b3b', 'border-color': '#e06666' } },
  { selector: 'node.focus', style: { 'overlay-color': '#7aa2f7', 'overlay-opacity': 0.25, 'overlay-padding': 6 } },
  { selector: 'node.selected', style: { 'underlay-color': '#7aa2f7', 'underlay-opacity': 0.35, 'underlay-padding': 6 } },
  {
    selector: 'edge',
    style: {
      width: 2,
      'curve-style': 'bezier',
      'line-color': '#4b5363',
      'target-arrow-color': '#4b5363',
      'target-arrow-shape': 'triangle',
      label: 'data(protocol)',
      'font-size': 8,
      color: '#7d8590',
      'text-background-color': '#0b0d10',
      'text-background-opacity': 1,
      'text-background-padding': 2,
    },
  },
  { selector: 'edge.attack', style: { 'line-color': '#a04545', 'target-arrow-color': '#a04545' } },
  { selector: 'edge.blocked', style: { 'line-style': 'dashed', 'line-color': '#2d323b', 'target-arrow-color': '#2d323b', color: '#4b5363' } },
  { selector: 'edge.sim-blocked', style: { 'line-style': 'dashed', 'line-color': '#5f8f6a', 'target-arrow-color': '#5f8f6a' } },
  { selector: 'edge.focus', style: { width: 4, 'line-color': '#7aa2f7', 'target-arrow-color': '#7aa2f7' } },
]

export default function NetworkGraph({ network, view, onSelectNode, onSelectEdge }) {
  const ref = useRef(null)
  const cyRef = useRef(null)
  const handlers = useRef({ onSelectNode, onSelectEdge })
  handlers.current = { onSelectNode, onSelectEdge }

  // Rebuild elements when topology changes
  useEffect(() => {
    if (!network) return
    const elements = [
      ...(network.nodes || []).map((n) => ({
        data: { ...n, label: `${n.name}\n${n.type} · C${n.criticality}` },
      })),
      ...(network.edges || []).map((e) => ({
        data: { ...e, id: `${e.source}->${e.target}` },
      })),
    ]

    // Choose layout: breadthfirst if directed edges exist, otherwise concentric or grid
    const hasEdges = (network.edges || []).length > 0
    const layoutConfig = hasEdges
      ? { name: 'breadthfirst', directed: true, spacingFactor: 1.3, padding: 35 }
      : { name: 'concentric', minNodeSpacing: 50, padding: 35 }

    const cy = cytoscape({
      container: ref.current,
      elements,
      style,
      layout: layoutConfig,
      minZoom: 0.2,
      maxZoom: 3.0,
    })

    cy.on('tap', 'node', (e) => handlers.current.onSelectNode?.(e.target.id()))
    cy.on('tap', 'edge', (e) => handlers.current.onSelectEdge?.(e.target.data('source'), e.target.data('target')))
    
    // Clicking graph background deselects
    cy.on('tap', (e) => {
      if (e.target === cy) {
        handlers.current.onSelectNode?.(null)
      }
    })

    cyRef.current = cy
    return () => cy.destroy()
  }, [network])

  // Apply highlight classes
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.batch(() => {
      cy.elements().removeClass('reachable compromised focus selected attack blocked sim-blocked')
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
    })
  }, [view, network])

  return <div ref={ref} className="h-full w-full" />
}
