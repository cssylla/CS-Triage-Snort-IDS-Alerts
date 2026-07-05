import { useState, useEffect, useCallback, useMemo } from 'react'
import Spinner from './Spinner'

const API_BASE = 'http://localhost:3001/api'

// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreColor(score) {
  if (score == null) return null
  if (score >= 8) return 'red'
  if (score >= 4) return 'yellow'
  return 'green'
}

function scoreLabel(score) {
  if (score == null) return '—'
  if (score >= 8) return 'Critical'
  if (score >= 6) return 'High'
  if (score >= 4) return 'Medium'
  return 'Low'
}

const SCORE_PILL = {
  red:    'bg-red-500/20 text-red-400 border border-red-500/40',
  yellow: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40',
  green:  'bg-green-500/15 text-green-400 border border-green-500/30',
}

const SCORE_TEXT = {
  red: 'text-red-400', yellow: 'text-yellow-400', green: 'text-green-400',
}

const ROW_ACCENT = {
  red:    'border-l-2 border-red-500 bg-red-500/[0.06]',
  yellow: 'border-l-2 border-yellow-500 bg-yellow-500/[0.05]',
  green:  'border-l-2 border-green-500 bg-green-500/[0.04]',
}

const FP_TEXT   = { low: 'text-green-400', medium: 'text-yellow-400', high: 'text-red-400' }
const FP_LABELS = { low: 'LOW', medium: 'MED', high: 'HIGH' }
const FP_ORDER  = { low: 0, medium: 1, high: 2 }

// ── Sortable column header ────────────────────────────────────────────────────

function SortableHeader({ col, label, sortKey, sortDir, onSort, className = '' }) {
  const active = sortKey === col
  return (
    <th
      className={`px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-widest select-none cursor-pointer group ${className} ${active ? 'text-sky-400' : 'text-slate-500 hover:text-slate-300'} transition-colors`}
      onClick={() => onSort(col)}
    >
      <span className="flex items-center gap-1">
        {label}
        <span className="text-[9px] ml-0.5">
          {active
            ? sortDir === 'asc' ? '▲' : '▼'
            : <span className="text-slate-700 group-hover:text-slate-500 transition-colors">⇅</span>}
        </span>
      </span>
    </th>
  )
}



// ── Stat chip ─────────────────────────────────────────────────────────────────

function Chip({ children, variant = 'default' }) {
  const base = 'inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium border'
  const vars = {
    default:  'bg-slate-800 border-slate-700 text-slate-400',
    done:     'bg-green-500/10 border-green-500/30 text-green-400',
    critical: 'bg-red-500/10 border-red-500/30 text-red-400',
    pending:  'bg-sky-500/10 border-sky-500/30 text-sky-400',
  }
  return <span className={`${base} ${vars[variant]}`}>{children}</span>
}

// ── Expanded detail panel ─────────────────────────────────────────────────────

function KV({ label, children, mono = false }) {
  return (
    <div className="flex gap-3 py-1 border-b border-slate-700/50 last:border-0 items-start">
      <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-500 w-24 shrink-0 pt-0.5">
        {label}
      </span>
      <span className={`text-[12px] text-slate-300 flex-1 leading-relaxed ${mono ? 'font-mono text-sky-300' : ''}`}>
        {children}
      </span>
    </div>
  )
}

function ExpandedRow({ alert, triage, loading, onTriage, colSpan }) {
  return (
    <tr className="bg-slate-900/80">
      <td colSpan={colSpan} className="px-0 py-0">
        <div className="grid grid-cols-1 lg:grid-cols-2 border-t border-slate-700/60">

          {/* ── Left: raw alert ── */}
          <div className="p-5 border-b lg:border-b-0 lg:border-r border-slate-700/60">
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3">
              Alert Details
            </p>
            <KV label="Rule">{alert.rule_message}</KV>
            <KV label="Source" mono>
              {alert.src_ip}{alert.src_port ? `:${alert.src_port}` : ''}
            </KV>
            <KV label="Destination" mono>
              {alert.dst_ip}{alert.dst_port ? `:${alert.dst_port}` : ''}
            </KV>
            <KV label="Protocol">
              <span className="font-mono text-sky-300">{alert.protocol}</span>
            </KV>
            {alert.flags && <KV label="Flags"><span className="font-mono text-slate-400">{alert.flags}</span></KV>}
            {alert.count != null && (
              <KV label="Event count">
                <span className="font-mono">{alert.count.toLocaleString()}</span>
              </KV>
            )}
            {alert.payload_snippet && (
              <KV label="Payload">
                <code className="text-red-400 bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded text-[11px] font-mono break-all">
                  {alert.payload_snippet}
                </code>
              </KV>
            )}

            {/* Per-row triage button */}
            <div className="mt-4">
              {loading ? (
                <div className="flex items-center gap-2 text-slate-400 text-[12px]">
                  <Spinner sm /> Analyzing…
                </div>
              ) : (
                <button
                  onClick={(e) => { e.stopPropagation(); onTriage(alert) }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-sky-600/20 border border-sky-500/40 text-sky-300 text-[12px] font-medium hover:bg-sky-600/30 transition-colors cursor-pointer"
                >
                  {triage ? '🔄 Re-run triage' : '🔍 Run triage'}
                </button>
              )}
            </div>
          </div>

          {/* ── Right: triage output ── */}
          <div className="p-5">
            {loading && !triage ? (
              <div className="flex items-center gap-2 text-slate-400 text-[13px] h-full">
                <Spinner /> Running triage…
              </div>
            ) : triage ? (
              <>
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3">
                  AI Triage
                  <span className="ml-2 font-mono normal-case tracking-normal text-sky-500/70">claude-sonnet-4-6</span>
                </p>

                {/* Score */}
                <div className="flex items-center gap-3 mb-3">
                  {(() => {
                    const c = scoreColor(triage.severity_score)
                    return (
                      <>
                        <span className={`font-mono font-bold text-lg ${SCORE_TEXT[c]}`}>
                          {triage.severity_score}<span className="text-slate-600 text-sm">/10</span>
                        </span>
                        <span className={`text-xs font-bold px-2 py-0.5 rounded ${SCORE_PILL[c]}`}>
                          {scoreLabel(triage.severity_score)}
                        </span>
                        <span className="text-[11px] text-slate-400 italic flex-1">
                          {triage.severity_justification}
                        </span>
                      </>
                    )
                  })()}
                </div>

                <KV label="MITRE Tactic">
                  <span className="font-mono text-violet-300 bg-violet-500/10 border border-violet-500/20 px-1.5 py-0.5 rounded text-[11px]">
                    {triage.mitre_tactic}
                  </span>
                </KV>
                <KV label="Technique">
                  <span className="font-mono text-violet-300/80 text-[11px]">{triage.mitre_technique}</span>
                </KV>
                <KV label="False Positive">
                  <span className={`font-bold text-[12px] ${FP_TEXT[triage.false_positive_likelihood]}`}>
                    {(triage.false_positive_likelihood ?? '—').toUpperCase()}
                  </span>
                </KV>

                {/* Action */}
                <div className="mt-3 p-3 rounded bg-yellow-500/5 border border-yellow-500/20">
                  <p className="text-[10px] font-bold uppercase tracking-wide text-yellow-500/70 mb-1">
                    ⚡ Recommended Action
                  </p>
                  <p className="text-[12px] text-yellow-200/90 leading-relaxed">{triage.recommended_action}</p>
                </div>

                {/* Summary */}
                <div className="mt-3 p-3 rounded bg-slate-800/60 border border-slate-700/60">
                  <p className="text-[10px] font-bold uppercase tracking-wide text-slate-500 mb-1">
                    📋 Incident Summary — NIST SP 800-61
                  </p>
                  <p className="text-[12px] text-slate-300 leading-relaxed">{triage.incident_summary}</p>
                </div>
              </>
            ) : (
              <div className="flex flex-col items-center justify-center h-full gap-2 text-slate-500 text-[13px] py-6">
                <span className="text-2xl">🔍</span>
                <span>Click "Run triage" to analyse this alert</span>
              </div>
            )}
          </div>
        </div>
      </td>
    </tr>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────

const FP_FILTER_OPTIONS = [
  { value: 'all',    label: 'All alerts' },
  { value: 'high',   label: 'High false positive' },
  { value: 'medium', label: 'Medium false positive' },
  { value: 'low',    label: 'Low false positive' },
]

const STORAGE_KEY = 'soc-triage-results'

export default function TriageTable({ alerts = [], triageMap = {}, setTriageMap = () => {} }) {

  const [loadingSet, setLoadingSet]   = useState(new Set())
  const [errorMap, setErrorMap]       = useState({})
  const [expandedId, setExpandedId]   = useState(null)
  const [globalError, setGlobalError] = useState(null)
  const [triagingAll, setTriagingAll] = useState(false)
  const [fpFilter, setFpFilter]       = useState('all')
  const [selectedIds, setSelectedIds] = useState(new Set())
  const [sortKey, setSortKey]         = useState('time')
  const [sortDir, setSortDir]         = useState('asc')

  const triageSingle = useCallback(async (alert) => {
    setLoadingSet(prev => new Set(prev).add(alert.id))
    setErrorMap(prev => { const n = { ...prev }; delete n[alert.id]; return n })
    try {
      const res  = await fetch(`${API_BASE}/triage`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ alert }),
      })
      const data = await res.json()
      if (data.success) {
        const next = { ...triageMap, [alert.id]: data.triage }
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(next)) } catch {}
        setTriageMap(next)
      } else {
        setErrorMap(prev => ({ ...prev, [alert.id]: data.error || 'Triage failed' }))
      }
    } catch {
      setErrorMap(prev => ({ ...prev, [alert.id]: 'Network error' }))
    } finally {
      setLoadingSet(prev => { const n = new Set(prev); n.delete(alert.id); return n })
    }
  }, [triageMap, setTriageMap])

  // Triage all alerts (or all selected if any are checked)
  const triageAll = async () => {
    const targets = selectedIds.size > 0
      ? alerts.filter(a => selectedIds.has(a.id))
      : alerts
    setTriagingAll(true)
    await Promise.all(targets.map(a => triageSingle(a)))
    setTriagingAll(false)
  }

  const toggleSelect = (id, e) => {
    e.stopPropagation()
    setSelectedIds(prev => {
      const n = new Set(prev)
      n.has(id) ? n.delete(id) : n.add(id)
      return n
    })
  }

  const toggleSelectAll = () => {
    setSelectedIds(prev =>
      prev.size === visibleAlerts.length
        ? new Set()
        : new Set(visibleAlerts.map(a => a.id))
    )
  }

  const toggleRow = (id) => setExpandedId(prev => prev === id ? null : id)

  const handleSort = (col) => {
    if (col === sortKey) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(col)
      setSortDir('asc')
    }
  }

  // Apply false-positive filter (only on triaged rows; untriaged always show)
  const filteredAlerts = alerts.filter(a => {
    if (fpFilter === 'all') return true
    const t = triageMap[a.id]
    if (!t) return true
    return t.false_positive_likelihood === fpFilter
  })

  // Apply sort
  const visibleAlerts = useMemo(() => {
    const dir = sortDir === 'asc' ? 1 : -1
    return [...filteredAlerts].sort((a, b) => {
      const ta = triageMap[a.id]
      const tb = triageMap[b.id]
      switch (sortKey) {
        case 'id':
          return dir * a.id.localeCompare(b.id)
        case 'time':
          return dir * (new Date(a.timestamp) - new Date(b.timestamp))
        case 'rule':
          return dir * a.rule_message.localeCompare(b.rule_message)
        case 'proto':
          return dir * a.protocol.localeCompare(b.protocol)
        case 'score': {
          const sa = ta?.severity_score ?? -1
          const sb = tb?.severity_score ?? -1
          return dir * (sa - sb)
        }
        case 'mitre':
          return dir * ((ta?.mitre_tactic ?? '').localeCompare(tb?.mitre_tactic ?? ''))
        case 'fp': {
          const fa = FP_ORDER[ta?.false_positive_likelihood] ?? -1
          const fb = FP_ORDER[tb?.false_positive_likelihood] ?? -1
          return dir * (fa - fb)
        }
        default:
          return 0
      }
    })
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filteredAlerts, triageMap, sortKey, sortDir])

  // Stats
  const doneCount     = Object.keys(triageMap).length
  const totalCount    = alerts.length
  const criticalCount = Object.values(triageMap).filter(t => t.severity_score >= 8).length
  const pendingCount  = totalCount - doneCount
  const allSelected   = selectedIds.size > 0 && selectedIds.size === visibleAlerts.length

  const triageLabel = () => {
    if (triagingAll) return <><Spinner sm /> Running…</>
    if (selectedIds.size > 0) return `⚡ Triage selected (${selectedIds.size})`
    return '⚡ Triage all'
  }

  const COL_COUNT = 8  // checkbox + id + time + rule + proto + score + mitre + fp

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans">

      {/* ══ Header ══════════════════════════════════════════════════════════ */}
      <header className="sticky top-0 z-50 bg-slate-900 border-b border-slate-700/80 shadow-lg shadow-black/30">
        <div className="px-6 py-4 flex items-start justify-between gap-4 flex-wrap">

          {/* Title block */}
          <div>
            <div className="flex items-center gap-2.5">
              <span className="text-xl">🛡️</span>
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">
                SOC Alert Triage Agent
              </h1>
              <span className="text-[10px] font-mono text-sky-400/80 border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 rounded-full">
                claude-sonnet-4-6
              </span>
            </div>
            <p className="text-[12px] text-slate-500 mt-0.5 ml-8">
              AI-assisted Snort IDS triage · MITRE ATT&CK mapping · NIST SP 800-61 summaries
            </p>
          </div>

          {/* Controls */}
          <div className="flex items-center gap-3 flex-wrap">

            {/* Stat chips */}
            {totalCount > 0 && (
              <div className="flex items-center gap-2">
                <Chip>{totalCount} alerts</Chip>
                {doneCount > 0 && <Chip variant="done">{doneCount}/{totalCount} triaged</Chip>}
                {pendingCount > 0 && doneCount > 0 && <Chip variant="pending">{pendingCount} pending</Chip>}
                {criticalCount > 0 && <Chip variant="critical">🔴 {criticalCount} critical</Chip>}
              </div>
            )}

            {/* FP filter */}
            <div className="relative">
              <select
                value={fpFilter}
                onChange={e => setFpFilter(e.target.value)}
                className="appearance-none bg-slate-800 border border-slate-600 text-slate-300 text-[12px] rounded px-3 py-1.5 pr-7 cursor-pointer hover:border-slate-500 focus:outline-none focus:border-sky-500 transition-colors"
              >
                {FP_FILTER_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
              <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 text-[10px]">▾</span>
            </div>

            {/* Clear cache */}
            {doneCount > 0 && (
              <button
                onClick={() => {
                  try { localStorage.removeItem(STORAGE_KEY) } catch {}
                  setTriageMap({})
                }}
                title="Clear all saved triage results"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-slate-600 bg-slate-800 hover:border-red-500/50 hover:text-red-400 text-slate-400 text-[12px] transition-colors cursor-pointer"
              >
                🗑 Clear cache
              </button>
            )}

            {/* Triage button */}
            <button
              onClick={triageAll}
              disabled={totalCount === 0}
              className="flex items-center gap-2 px-4 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-[13px] font-semibold transition-colors cursor-pointer"
            >
              {triageLabel()}
            </button>
          </div>
        </div>
      </header>

      {/* ══ Errors / Loading ════════════════════════════════════════════════ */}
      {globalError && (
        <div className="mx-6 mt-4 p-3 rounded bg-red-500/10 border border-red-500/30 text-red-300 text-[13px]">
          ⚠️ {globalError}
        </div>
      )}

      {alerts.length === 0 && (
        <div className="flex items-center gap-2 px-6 py-12 text-slate-500 text-[13px]">
          <span>No alerts loaded.</span>
        </div>
      )}

      {/* ══ Table ════════════════════════════════════════════════════════════ */}
      {alerts.length > 0 && visibleAlerts.length > 0 && (
        <div className="px-6 py-4 overflow-x-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead>
              <tr className="bg-slate-900 border-b-2 border-slate-700">
                {/* Checkbox all */}
                <th className="w-10 px-3 py-2.5 text-left">
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={toggleSelectAll}
                    className="accent-sky-500 cursor-pointer w-3.5 h-3.5"
                  />
                </th>
                <SortableHeader col="id"    label="ID"             sortKey={sortKey} sortDir={sortDir} onSort={handleSort} className="w-28" />
                <SortableHeader col="time"  label="Time"           sortKey={sortKey} sortDir={sortDir} onSort={handleSort} className="w-20" />
                <SortableHeader col="rule"  label="Rule / Signature" sortKey={sortKey} sortDir={sortDir} onSort={handleSort} />
                <SortableHeader col="proto" label="Proto"          sortKey={sortKey} sortDir={sortDir} onSort={handleSort} className="w-16" />
                <SortableHeader col="score" label="Score"          sortKey={sortKey} sortDir={sortDir} onSort={handleSort} className="w-28" />
                <SortableHeader col="mitre" label="MITRE"          sortKey={sortKey} sortDir={sortDir} onSort={handleSort} className="w-52" />
                <SortableHeader col="fp"    label="False+"         sortKey={sortKey} sortDir={sortDir} onSort={handleSort} className="w-16" />
              </tr>
            </thead>
            <tbody>
              {visibleAlerts.map(alert => {
                const triage   = triageMap[alert.id]
                const loading  = loadingSet.has(alert.id)
                const err      = errorMap[alert.id]
                const expanded = expandedId === alert.id
                const color    = scoreColor(triage?.severity_score)
                const selected = selectedIds.has(alert.id)

                return (
                  <>
                    <tr
                      key={alert.id}
                      onClick={() => toggleRow(alert.id)}
                      className={[
                        'border-b border-slate-800 cursor-pointer transition-colors group',
                        color ? ROW_ACCENT[color] : 'border-l-2 border-transparent',
                        expanded  ? 'bg-slate-800/60' : 'hover:bg-slate-800/40',
                        selected  ? 'ring-1 ring-inset ring-sky-500/30' : '',
                        loading   ? 'opacity-70' : '',
                      ].join(' ')}
                    >
                      {/* Checkbox */}
                      <td className="px-3 py-3" onClick={e => toggleSelect(alert.id, e)}>
                        <input
                          type="checkbox"
                          checked={selected}
                          onChange={() => {}}
                          className="accent-sky-500 cursor-pointer w-3.5 h-3.5"
                        />
                      </td>

                      {/* ID */}
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-600 text-[10px] group-hover:text-slate-400 transition-colors">
                            {expanded ? '▾' : '▸'}
                          </span>
                          <span className="font-mono text-[11px] text-slate-400">{alert.id}</span>
                        </div>
                      </td>

                      {/* Time */}
                      <td className="px-3 py-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                        {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>

                      {/* Rule */}
                      <td className="px-3 py-3 max-w-0">
                        <span className="block truncate text-slate-200">{alert.rule_message}</span>
                      </td>

                      {/* Protocol */}
                      <td className="px-3 py-3">
                        <span className="font-mono text-[10px] font-bold text-sky-300 bg-sky-500/10 border border-sky-500/20 px-2 py-0.5 rounded">
                          {alert.protocol}
                        </span>
                      </td>

                      {/* Score */}
                      <td className="px-3 py-3">
                        {loading ? (
                          <Spinner sm />
                        ) : err ? (
                          <span className="text-red-400 text-[11px] font-bold" title={err}>ERR</span>
                        ) : triage ? (
                          <div className="flex items-center gap-1.5">
                            <span className={`font-mono font-bold text-sm w-5 text-center ${SCORE_TEXT[color]}`}>
                              {triage.severity_score}
                            </span>
                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${SCORE_PILL[color]}`}>
                              {scoreLabel(triage.severity_score)}
                            </span>
                          </div>
                        ) : (
                          <span className="text-slate-600 text-[11px]">—</span>
                        )}
                      </td>

                      {/* MITRE */}
                      <td className="px-3 py-3">
                        {loading ? <Spinner sm /> : triage ? (
                          <div className="flex flex-col gap-0.5 min-w-0">
                            <span className="font-mono text-[10px] text-violet-300 truncate">
                              {triage.mitre_tactic}
                            </span>
                            <span className="font-mono text-[10px] text-slate-500 truncate">
                              {triage.mitre_technique}
                            </span>
                          </div>
                        ) : <span className="text-slate-600 text-[11px]">—</span>}
                      </td>

                      {/* False positive */}
                      <td className="px-3 py-3">
                        {loading ? <Spinner sm /> : triage ? (
                          <span className={`font-mono text-[10px] font-bold ${FP_TEXT[triage.false_positive_likelihood] ?? 'text-slate-400'}`}>
                            {FP_LABELS[triage.false_positive_likelihood] ?? '—'}
                          </span>
                        ) : <span className="text-slate-600 text-[11px]">—</span>}
                      </td>
                    </tr>

                    {/* Expanded panel */}
                    {expanded && (
                      <ExpandedRow
                        key={`${alert.id}-exp`}
                        alert={alert}
                        triage={triage}
                        loading={loading}
                        onTriage={triageSingle}
                        colSpan={COL_COUNT}
                      />
                    )}
                  </>
                )
              })}
            </tbody>
          </table>

          {/* Empty-filter state */}
          {visibleAlerts.length === 0 && fpFilter !== 'all' && (
            <div className="text-center py-12 text-slate-500 text-[13px]">
              No triaged alerts match the "{fpFilter}" false-positive filter.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
