import { useState, useRef } from 'react'
import { api } from '../api'
import { Icon } from './ui'

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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-xs p-4 select-none">
      <div className="relative w-full max-w-xl rounded-lg border border-line bg-s1 shadow-2xl text-fg flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="flex h-12 items-center justify-between border-b border-line px-5">
          <div className="flex items-center gap-2.5">
            <span className="badge badge-accent mono font-bold">ZEEK</span>
            <h2 className="text-sm font-semibold tracking-wide text-fg">
              Import Zeek Connection Logs
            </h2>
          </div>
          <button
            onClick={onClose}
            className="btn btn-ghost btn-icon"
            title="Close"
          >
            <Icon name="x" />
          </button>
        </div>

        <div className="overflow-y-auto flex-1 p-5 space-y-4 text-xs">
          {/* Dropzone */}
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-5 text-center cursor-pointer transition-colors ${
              isDragging
                ? 'border-accent bg-accent/10'
                : file
                ? 'border-accent/40 bg-accent/5'
                : 'border-line hover:border-line-strong bg-s2/40'
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
                <p className="font-semibold text-accent text-sm">{file.name}</p>
                <p className="mono text-[11px] text-fg-subtle">
                  {(file.size / 1024).toFixed(1)} KB · Click or drop another file to replace
                </p>
              </div>
            ) : (
              <div className="space-y-1.5">
                <Icon name="upload" size={20} className="mx-auto text-fg-subtle" />
                <p className="font-medium text-fg">
                  Drop Zeek <span className="text-accent mono">conn.log</span> here, or click to browse
                </p>
                <p className="text-[11px] text-fg-subtle">
                  Supports TSV with directives (#fields) or JSON (up to 50 MB / 50,000 flows)
                </p>
              </div>
            )}
          </div>

          {/* Settings Grid */}
          <div className="grid grid-cols-2 gap-3 rounded-md border border-line bg-s2/40 p-3">
            <div>
              <label className="label">Import Mode</label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                className="input"
              >
                <option value="replace" className="bg-s2">Replace active network completely</option>
                <option value="merge" className="bg-s2">Merge into existing network</option>
              </select>
              <p className="text-[10px] text-fg-subtle mt-1">
                {mode === 'replace' ? 'Clears active canvas' : 'Preserves existing devices'}
              </p>
            </div>

            <div>
              <label className="label">Discovered Host Criticality</label>
              <select
                value={defaultCriticality}
                onChange={(e) => setDefaultCriticality(Number(e.target.value))}
                className="input mono"
              >
                <option value={1} className="bg-s2">1 - Low / Ephemeral</option>
                <option value={2} className="bg-s2">2 - Standard (Default)</option>
                <option value={3} className="bg-s2">3 - Elevated</option>
                <option value={4} className="bg-s2">4 - High Criticality</option>
                <option value={5} className="bg-s2">5 - Mission Critical</option>
              </select>
              <p className="text-[10px] text-fg-subtle mt-1">Default for newly inferred IPs</p>
            </div>

            <div>
              <label className="label">Default Trust Zone</label>
              <select
                value={defaultZone}
                onChange={(e) => setDefaultZone(e.target.value)}
                className="input"
              >
                <option value="internal" className="bg-s2">internal (RFC 1918 Private)</option>
                <option value="dmz" className="bg-s2">dmz (Public / Perimeter)</option>
                <option value="employee" className="bg-s2">employee</option>
                <option value="restricted" className="bg-s2">restricted</option>
              </select>
            </div>

            <div>
              <label className="label">Traffic Policy Default</label>
              <label className="flex items-center gap-2 mt-1.5 cursor-pointer text-xs text-fg-muted">
                <input
                  type="checkbox"
                  checked={allowedDefault}
                  onChange={(e) => setAllowedDefault(e.target.checked)}
                  className="accent-accent"
                />
                <span>Set as Policy Allowed</span>
              </label>
              <p className="text-[10px] text-warn mt-1">
                {allowedDefault
                  ? 'Warning: Observed flows will be traversable by attack simulation'
                  : 'Recommended: Observed flows are logged without opening access'}
              </p>
            </div>
          </div>

          {mode === 'merge' && (
            <div className="rounded border border-accent/30 bg-accent/5 p-2.5">
              <label className="flex items-center gap-2 cursor-pointer text-xs">
                <input
                  type="checkbox"
                  checked={preserveExisting}
                  onChange={(e) => setPreserveExisting(e.target.checked)}
                  className="accent-accent"
                />
                <span className="text-fg font-medium">Preserve attributes of existing devices</span>
              </label>
              <p className="text-[10px] text-fg-subtle mt-0.5 ml-5">
                Existing names, criticality ratings, and security zones will not be overwritten by log inference.
              </p>
            </div>
          )}

          {error && (
            <div className="rounded border border-danger/40 bg-danger/10 p-2.5 text-danger text-xs leading-relaxed">
              <strong>Import Error:</strong> {error}
            </div>
          )}

          {/* Preview Statistics Box */}
          {previewData && (
            <div className="rounded-md border border-ok/30 bg-ok/5 p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-ok flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-ok" />
                  Candidate Network Verified
                </span>
                <span className="text-[10px] mono text-fg-subtle">
                  {previewData.statistics?.processed_records} records processed
                </span>
              </div>

              <div className="grid grid-cols-4 gap-2 pt-1 font-mono text-center">
                <div className="rounded bg-s2 p-2 border border-line">
                  <div className="text-base font-bold text-fg">{previewData.nodes_count}</div>
                  <div className="text-[10px] text-fg-subtle">Devices</div>
                </div>
                <div className="rounded bg-s2 p-2 border border-line">
                  <div className="text-base font-bold text-fg">{previewData.edges_count}</div>
                  <div className="text-[10px] text-fg-subtle">Connections</div>
                </div>
                <div className="rounded bg-s2 p-2 border border-line">
                  <div className="text-base font-bold text-fg">{previewData.statistics?.skipped_records || 0}</div>
                  <div className="text-[10px] text-fg-subtle">Skipped/Loops</div>
                </div>
                <div className="rounded bg-s2 p-2 border border-line">
                  <div className="text-base font-bold text-fg">{previewData.warnings?.length || 0}</div>
                  <div className="text-[10px] text-fg-subtle">Warnings</div>
                </div>
              </div>

              {previewData.warnings?.length > 0 && (
                <div className="mt-2 max-h-24 overflow-y-auto rounded bg-s2 p-2 text-[10px] text-warn space-y-1 font-mono border border-line">
                  {previewData.warnings.map((w, i) => (
                    <div key={i}>⚠ {w}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between border-t border-line px-5 py-3 bg-s2/30">
          <button
            type="button"
            onClick={onClose}
            className="btn btn-secondary"
          >
            Cancel
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={loading || !file}
              onClick={handlePreview}
              className="btn btn-secondary"
            >
              {loading && !previewData ? 'Parsing...' : 'Preview Network'}
            </button>
            <button
              type="button"
              disabled={loading || !file}
              onClick={handleApply}
              className={`btn ${mode === 'replace' ? 'btn-danger' : 'btn-primary'}`}
            >
              {loading && previewData ? 'Applying...' : mode === 'replace' ? 'Replace Network' : 'Merge Network'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
