const BASE = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')

async function request(path, options = {}) {
  let res
  try {
    res = await fetch(`${BASE}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
      body: options.body ? JSON.stringify(options.body) : undefined,
    })
  } catch {
    throw new Error(`Cannot reach backend at ${BASE}`)
  }
  const data = await res.json().catch(() => null)
  if (!res.ok) {
    const detail = data?.detail
    const msg = Array.isArray(detail)
      ? detail.map((d) => d.msg).join('; ')
      : detail || `Request failed (${res.status})`
    throw new Error(msg)
  }
  return data
}

const enc = encodeURIComponent

export const api = {
  getNetwork: () => request('/network'),
  resetNetwork: () => request('/network/reset', { method: 'POST' }),
  clearNetwork: () => request('/network/clear', { method: 'POST' }),
  
  // Devices CRUD
  addDevice: (body) => request('/network/devices', { method: 'POST', body }),
  updateDevice: (id, body) => request(`/network/devices/${enc(id)}`, { method: 'PATCH', body }),
  deleteDevice: (id) => request(`/network/devices/${enc(id)}`, { method: 'DELETE' }),

  // Connections CRUD
  addConnection: (body) => request('/network/connections', { method: 'POST', body }),
  updateConnection: (s, t, body) =>
    request(`/network/connections/${enc(s)}/${enc(t)}`, { method: 'PATCH', body }),
  deleteConnection: (s, t) =>
    request(`/network/connections/${enc(s)}/${enc(t)}`, { method: 'DELETE' }),

  // Analysis & Algorithms
  analyze: (id) => request(`/analyze/${enc(id)}`),
  analyzeMulti: (ids) => request('/analyze/multi', { method: 'POST', body: { compromised_devices: ids } }),
  path: (s, t) => request(`/path/${enc(s)}/${enc(t)}`),
  risk: (id) => request(`/risk/${enc(id)}`),
  criticalAssets: (id, threshold) => request(`/critical-assets/${enc(id)}?threshold=${threshold}`),
  containment: (id, threshold) => request(`/containment/${enc(id)}?critical_threshold=${threshold}`),
  impact: (id, threshold) => request(`/containment/impact/${enc(id)}?critical_threshold=${threshold}`),
  simulate: (body) => request('/containment/simulate', { method: 'POST', body }),
}
