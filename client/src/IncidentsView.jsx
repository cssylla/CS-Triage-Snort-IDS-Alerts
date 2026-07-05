import { useState, useMemo } from 'react'
import { correlateIncidents, generateIncidentReport } from './incidentCorrelation'

function IncidentRow({ incident, triageMap, onExpand, expanded }) {
  const { incidentId, shortName, alerts, severityLevel, srcIPs, dstIPs } = incident

  const severityColor = {
    CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
    HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/30',
    MEDIUM:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
    LOW:      'text-green-400 bg-green-500/10 border-green-500/30',
  }

  const rowColor = {
    CRITICAL: 'border-l-2 border-red-500 bg-red-500/[0.06]',
    HIGH:     'border-l-2 border-orange-500 bg-orange-500/[0.05]',
    MEDIUM:   'border-l-2 border-yellow-500 bg-yellow-500/[0.05]',
    LOW:      'border-l-2 border-green-500 bg-green-500/[0.04]',
  }

  return (
    <>
      <tr
        onClick={() => onExpand(incident.incidentId)}
        className={`border-b border-slate-800 cursor-pointer transition-colors ${rowColor[severityLevel]} ${expanded ? 'bg-slate-800/60' : 'hover:bg-slate-800/40'}`}
      >
        <td className="px-3 py-3">
          <span className="text-slate-600 text-[10px]">{expanded ? '▾' : '▸'}</span>
        </td>
        <td className="px-3 py-3 font-mono text-[11px] text-slate-400">{incidentId}</td>
        <td className="px-3 py-3 text-slate-200">{shortName}</td>
        <td className="px-3 py-3 font-mono text-[11px]">
          <span className="text-sky-300">{srcIPs.join(', ')}</span>
        </td>
        <td className="px-3 py-3 font-mono text-[11px]">
          <span className="text-rose-300">{dstIPs.join(', ')}</span>
        </td>
        <td className="px-3 py-3 text-center font-mono text-[11px] text-slate-400">
          {alerts.length}
        </td>
        <td className="px-3 py-3">
          <span className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${severityColor[severityLevel]}`}>
            {severityLevel}
          </span>
        </td>
      </tr>

      {expanded && (
        <tr className="bg-slate-900/80 border-b-2 border-slate-700">
          <td colSpan={7} className="px-0 py-0">
            <div className="p-6">
              <div className="bg-slate-800/50 border border-slate-700 rounded p-4 font-mono text-[11px] text-slate-300 whitespace-pre-wrap overflow-auto max-h-96">
                {generateIncidentReport(incident, triageMap)}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

export default function IncidentsView({ alerts, triageMap }) {
  const [expandedId, setExpandedId] = useState(null)

  const incidents = useMemo(() => {
    if (alerts.length === 0) return []
    return correlateIncidents(alerts, triageMap)
  }, [alerts, triageMap])

  const criticalCount = incidents.filter(i => i.severityLevel === 'CRITICAL').length
  const highCount = incidents.filter(i => i.severityLevel === 'HIGH').length
  const totalAlertCount = incidents.reduce((sum, i) => sum + i.alerts.length, 0)

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans">
      {/* Header */}
      <header className="bg-slate-900 border-b border-slate-700/80 shadow-lg shadow-black/30">
        <div className="px-6 py-4">
          <div className="flex items-center gap-2.5 mb-2">
            <span className="text-xl">🔗</span>
            <h1 className="text-lg font-bold text-slate-100">Correlated Incidents</h1>
            <span className="text-[10px] font-mono text-slate-500 border border-slate-600 bg-slate-800 px-2 py-0.5 rounded-full">
              MITRE ATT&CK Campaign Analysis
            </span>
          </div>
          <p className="text-[12px] text-slate-500 ml-8">
            Temporal clustering · Progression analysis · Campaign severity assessment
          </p>

          {/* Stats */}
          {incidents.length > 0 && (
            <div className="flex items-center gap-2 mt-3">
              <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 border border-slate-600 text-slate-400">
                {incidents.length} incidents
              </span>
              <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 border border-slate-600 text-slate-400">
                {totalAlertCount} alerts
              </span>
              {criticalCount > 0 && (
                <span className="text-[11px] px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 font-semibold">
                  🔴 {criticalCount} critical
                </span>
              )}
              {highCount > 0 && (
                <span className="text-[11px] px-2 py-0.5 rounded bg-orange-500/10 border border-orange-500/30 text-orange-400 font-semibold">
                  🟠 {highCount} high
                </span>
              )}
            </div>
          )}
        </div>
      </header>

      {/* Content */}
      {incidents.length === 0 ? (
        <div className="text-center py-12 text-slate-500 text-[13px]">
          <span className="text-2xl block mb-2">📊</span>
          No incidents yet. Triage some alerts to begin correlation analysis.
        </div>
      ) : (
        <div className="px-6 py-4 overflow-x-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead>
              <tr className="bg-slate-900 border-b-2 border-slate-700">
                <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500 w-6" />
                <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500 w-40">Incident ID</th>
                <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500">Name / Description</th>
                <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500 w-40">Source IP(s)</th>
                <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500 w-40">Target IP(s)</th>
                <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500 w-20 text-center">Alerts</th>
                <th className="px-3 py-2.5 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500 w-24">Severity</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map(incident => (
                <IncidentRow
                  key={incident.incidentId}
                  incident={incident}
                  triageMap={triageMap}
                  onExpand={(id) => setExpandedId(prev => prev === id ? null : id)}
                  expanded={expandedId === incident.incidentId}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
