import { useState, useEffect } from 'react'
import TriageTable from './TriageTable'
import IncidentsView from './IncidentsView'

const API_BASE = 'http://localhost:3001/api'

export default function App() {
  const [view, setView] = useState('alerts')  // 'alerts' or 'incidents'
  const [alerts, setAlerts] = useState([])
  const [triageMap, setTriageMap] = useState(() => {
    try {
      const saved = localStorage.getItem('soc-triage-results')
      return saved ? JSON.parse(saved) : {}
    } catch {
      return {}
    }
  })
  const [fetching, setFetching] = useState(true)
  const [globalError, setGlobalError] = useState(null)

  // Load alerts on mount
  useEffect(() => {
    fetch(`${API_BASE}/alerts`)
      .then(r => r.json())
      .then(data => {
        if (data.success) setAlerts(data.alerts)
        else setGlobalError(data.error || 'Failed to load alerts')
      })
      .catch(err => setGlobalError(err.message))
      .finally(() => setFetching(false))
  }, [])

  if (fetching) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-200 flex items-center justify-center">
        <div className="text-center">
          <div className="inline-block rounded-full border-2 border-slate-600 border-t-sky-400 animate-spin w-8 h-8 mb-4" />
          <p className="text-slate-400">Loading…</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Global error banner */}
      {globalError && (
        <div className="bg-red-500/10 border-b border-red-500/30 px-6 py-3 text-red-300 text-[13px]">
          ⚠️ {globalError}
        </div>
      )}

      {/* View tabs */}
      <div className="sticky top-0 z-40 bg-slate-900/80 border-b border-slate-700/50 backdrop-blur-sm">
        <div className="flex items-center gap-1 px-6 h-12">
          <button
            onClick={() => setView('alerts')}
            className={`px-4 py-2 rounded text-[13px] font-semibold transition-colors ${
              view === 'alerts'
                ? 'bg-sky-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            🛡️ Alerts ({alerts.length})
          </button>
          <button
            onClick={() => setView('incidents')}
            className={`px-4 py-2 rounded text-[13px] font-semibold transition-colors ${
              view === 'incidents'
                ? 'bg-sky-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            🔗 Incidents
          </button>
        </div>
      </div>

      {/* Content */}
      {view === 'alerts' ? (
        <TriageTable alerts={alerts} triageMap={triageMap} setTriageMap={setTriageMap} />
      ) : (
        <IncidentsView alerts={alerts} triageMap={triageMap} />
      )}
    </div>
  )
}
