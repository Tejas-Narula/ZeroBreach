// Storage and asset mappings for Cytoscape network graph

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
  endpoint: '/computer.svg',
  server: '/server.svg',
  database: '/database.svg',
  network_device: '/router.svg',
  firewall: '/firewall.svg',
  wireless_access_point: '/wap.svg',
  cloud_infrastructure: '/cloud.svg',
  security_system: '/security.svg',
  iot_device: '/iot.svg',
  external: '/external.svg',
  unknown: '/unknown.svg',
  // Backward compatibility aliases
  laptop: '/computer.svg',
  workstation: '/computer.svg',
  computer: '/computer.svg',
  router: '/router.svg',
  hub: '/hub.svg',
}

// Drag & drop transfer state
let _draggedTemplate = null

export function getDraggedTemplate() {
  return _draggedTemplate
}

export function setDraggedTemplate(template) {
  _draggedTemplate = template
}

