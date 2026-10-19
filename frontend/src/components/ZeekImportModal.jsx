import { useState, useRef } from 'react'
import { api } from '../api'

export default function ZeekImportModal({ isOpen, onClose, onImportSuccess }) {
  const [file, setFile] = useState(null)
  const [mode, setMode] = useState('replace') // 'replace' | 'merge'
  const [defaultCriticality, setDefaultCriticality] = useState(2)
  const [defaultZone, setDefaultZone] = useState('internal')
  const [allowedDefault, setAllowedDefault] = useState(false)
  const [preserveExisting, setPreserveExisting] = useState(true)

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [previewData, setPreviewData] = useState(null)
  const [isDragging, setIsDragging] = useState(false)

  const fileInputRef = useRef(null)

  if (!isOpen) return null

  function handleFileChange(e) {
    const selected = e.target.files?.[0]
    if (selected) {
      setFile(selected)
      setError('')
      setPreviewData(null)
    }
  }

  function handleDragOver(e) {
    e.preventDefault()
    setIsDragging(true)
  }

  function handleDragLeave(e) {
    e.preventDefault()
    setIsDragging(false)
  }

  function handleDrop(e) {
    e.preventDefault()
    setIsDragging(false)
    const dropped = e.dataTransfer.files?.[0]
    if (dropped) {
      setFile(dropped)
      setError('')
      setPreviewData(null)
    }
  }

  function buildFormData(targetMode) {
    const fd = new FormData()
    fd.append('file', file)
    fd.append('mode', targetMode)
    fd.append('default_criticality', defaultCriticality)
    fd.append('default_zone', defaultZone)
    fd.append('allowed_default', allowedDefault)
    fd.append('preserve_existing_nodes', preserveExisting)
    return fd
  }

  async function handlePreview() {
    if (!file) {
      setError('Please select or drop a Zeek log file first.')
      return
    }
    setLoading(true)
    setError('')
    try {
      const data = await api.importZeek(buildFormData('preview'))
      setPreviewData(data)
    } catch (err) {
      setError(err.message)
      setPreviewData(null)
    } finally {
      setLoading(false)
    }
  }

  async function handleApply() {
    if (!file) {
      setError('Please select or drop a Zeek log file.')
      return
    }
    setLoading(true)
    setError('')
    try {
      const data = await api.importZeek(buildFormData(mode))
      onImportSuccess(data)
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4">
      <div className="relative w-full max-w-2xl rounded-lg border border-white/10 bg-[#0f1218] p-6 shadow-2xl text-zinc-100 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <span className="flex h-6 w-6 items-center justify-center rounded-md bg-emerald-500/10 text-emerald-400 font-mono text-xs font-bold border border-emerald-500/20">
              ZK
            </span>
            <h2 className="text-sm font-semibold tracking-wide text-zinc-100">
              Import Zeek Connection Logs
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-zinc-100 text-lg leading-none px-2 py-1"
            title="Close"
          >
            ×
          </button>
        </div>

        <div className="overflow-y-auto flex-1 pr-1 space-y-4 text-xs">
          {/* Dropzone */}
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-5 text-center cursor-pointer transition ${
              isDragging
                ? 'border-emerald-500 bg-emerald-500/10'
                : file
                ? 'border-sky-500/50 bg-sky-500/5'
                : 'border-white/15 hover:border-white/30 bg-white/[0.02]'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".log,.tsv,.json,.txt"
              onChange={handleFileChange}
              className="hidden"
            />
            {file ? (
              <div className="space-y-1">
                <p className="font-medium text-sky-400 text-sm">
                  {file.name}
                </p>
                <p className="text-[11px] text-zinc-400 font-mono">
                  {(file.size / 1024).toFixed(1)} KB · Click or drag another file to replace
                </p>
              </div>
            ) : (
              <div className="space-y-1">
                <p className="font-medium text-zinc-200">
                  Drop Zeek <span className="text-emerald-400">conn.log</span> (TSV or JSON) here, or click to browse
                </p>
                <p className="text-[11px] text-zinc-500">
                  Supports native Zeek TSV with directives (#fields) or newline-delimited JSON (up to 10MB)
                </p>
              </div>
            )}
          </div>

          {/* Import Settings Grid */}
          <div className="grid grid-cols-2 gap-3 rounded-md border border-white/5 bg-white/[0.02] p-3">
            <div>
              <label className="block text-[11px] font-medium text-zinc-400 mb-1">
                Import Mode
              </label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                className="w-full rounded border border-white/10 bg-[#161a22] px-2 py-1 text-xs text-zinc-200 focus:outline-none focus:border-sky-500"
              >
                <option value="replace">Replace active network completely</option>
                <option value="merge">Merge into existing network</option>
              </select>
              <p className="text-[10px] text-zinc-500 mt-1">
                {mode === 'replace'
                  ? 'Clears canvas and loads only nodes from log'
                  : 'Preserves existing devices and updates connections'}
              </p>
            </div>

            <div>
              <label className="block text-[11px] font-medium text-zinc-400 mb-1">
                Discovered Host Criticality
              </label>
              <select
                value={defaultCriticality}
                onChange={(e) => setDefaultCriticality(Number(e.target.value))}
                className="w-full rounded border border-white/10 bg-[#161a22] px-2 py-1 text-xs text-zinc-200 focus:outline-none focus:border-sky-500"
              >
                <option value={1}>1 - Low / Ephemeral</option>
                <option value={2}>2 - Standard (Default)</option>
                <option value={3}>3 - Elevated</option>
                <option value={4}>4 - High Criticality</option>
                <option value={5}>5 - Mission Critical</option>
              </select>
              <p className="text-[10px] text-zinc-500 mt-1">
                Conservative baseline for newly inferred IPs
              </p>
            </div>

            <div>
              <label className="block text-[11px] font-medium text-zinc-400 mb-1">
                Default Trust Zone
              </label>
              <select
                value={defaultZone}
                onChange={(e) => setDefaultZone(e.target.value)}
                className="w-full rounded border border-white/10 bg-[#161a22] px-2 py-1 text-xs text-zinc-200 focus:outline-none focus:border-sky-500"
              >
                <option value="internal">internal (RFC 1918 Private)</option>
                <option value="dmz">dmz (Public / Perimeter)</option>
                <option value="employee">employee</option>
                <option value="restricted">restricted</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-medium text-zinc-400 mb-1">
                Traffic Authorization Policy
              </label>
              <label className="flex items-center gap-2 mt-1 cursor-pointer">
                <input
                  type="checkbox"
                  checked={allowedDefault}
                  onChange={(e) => setAllowedDefault(e.target.checked)}
                  className="rounded border-white/20 bg-[#161a22] text-sky-500"
                />
                <span className="text-zinc-300">Default to Policy Allowed</span>
              </label>
              <p className="text-[10px] text-amber-400/90 mt-1">
                {allowedDefault
                  ? 'WARNING: Observed flows will be traversable by attack simulation'
                  : 'Recommended: Observed flows are logged without opening access'}
              </p>
            </div>
          </div>

          {/* Merge Option Checkbox */}
          {mode === 'merge' && (
            <div className="rounded border border-sky-500/20 bg-sky-500/5 p-2.5">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={preserveExisting}
                  onChange={(e) => setPreserveExisting(e.target.checked)}
                  className="rounded border-white/20 bg-[#161a22] text-sky-500"
                />
                <span className="text-zinc-200 font-medium">Preserve attributes of existing devices</span>
              </label>
              <p className="text-[10px] text-zinc-400 mt-0.5 ml-5">
                Existing names, criticality ratings, and security zones will not be overwritten by log inference.
              </p>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="rounded border border-red-500/30 bg-red-500/10 p-2.5 text-red-300 text-[11px] leading-relaxed">
              <strong>Import Error:</strong> {error}
            </div>
          )}

          {/* Preview Statistics Box */}
          {previewData && (
            <div className="rounded-md border border-emerald-500/30 bg-emerald-500/5 p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-emerald-400 flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-emerald-500" />
                  Candidate Network Verified
                </span>
                <span className="text-[10px] font-mono text-zinc-400">
                  {previewData.statistics?.processed_records} records processed
                </span>
              </div>

              <div className="grid grid-cols-4 gap-2 pt-1 font-mono text-center">
                <div className="rounded bg-black/40 p-1.5">
                  <div className="text-base font-bold text-zinc-100">{previewData.nodes_count}</div>
                  <div className="text-[10px] text-zinc-400">Devices</div>
                </div>
                <div className="rounded bg-black/40 p-1.5">
                  <div className="text-base font-bold text-zinc-100">{previewData.edges_count}</div>
                  <div className="text-[10px] text-zinc-400">Connections</div>
                </div>
                <div className="rounded bg-black/40 p-1.5">
                  <div className="text-base font-bold text-zinc-100">{previewData.statistics?.skipped_records || 0}</div>
                  <div className="text-[10px] text-zinc-400">Skipped/Loops</div>
                </div>
                <div className="rounded bg-black/40 p-1.5">
                  <div className="text-base font-bold text-zinc-100">{previewData.warnings?.length || 0}</div>
                  <div className="text-[10px] text-zinc-400">Warnings</div>
                </div>
              </div>

              {previewData.warnings && previewData.warnings.length > 0 && (
                <div className="mt-2 max-h-24 overflow-y-auto rounded bg-black/30 p-2 text-[10px] text-amber-300 space-y-1 font-mono">
                  {previewData.warnings.map((w, i) => (
                    <div key={i}>⚠ {w}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between border-t border-white/10 pt-3 mt-4">
          <button
            type="button"
            onClick={onClose}
            className="rounded bg-white/5 px-3 py-1.5 text-xs text-zinc-300 hover:bg-white/10 transition"
          >
            Cancel
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={loading || !file}
              onClick={handlePreview}
              className="rounded border border-sky-500/40 bg-sky-500/10 px-3 py-1.5 text-xs font-medium text-sky-300 hover:bg-sky-500/20 disabled:opacity-40 transition"
            >
              {loading && !previewData ? 'Parsing...' : 'Preview Network'}
            </button>
            <button
              type="button"
              disabled={loading || !file}
              onClick={handleApply}
              className={`rounded px-4 py-1.5 text-xs font-medium text-white shadow-sm disabled:opacity-40 transition ${
                mode === 'replace'
                  ? 'bg-red-600 hover:bg-red-500'
                  : 'bg-emerald-600 hover:bg-emerald-500'
              }`}
            >
              {loading && previewData ? 'Applying...' : mode === 'replace' ? 'Replace Network' : 'Merge Network'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
