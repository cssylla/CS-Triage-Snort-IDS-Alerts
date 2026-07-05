// ── Incident correlation engine ──────────────────────────────────────────────
// Groups individual Snort alerts into correlated security incidents using:
// - Temporal clustering (5-15 min windows)
// - Host-based progression (same src/dst over time)
// - Lateral progression (chain of attacks)
// - Attack phase classification

const ATTACK_PHASES = {
  'Reconnaissance': ['SCAN', 'Network Service Scanning', 'Port Scan', 'Ping Sweep'],
  'Exploitation': ['Exploit', 'SQL Injection', 'Buffer Overflow', 'RCE', 'CVE'],
  'Command and Control': ['C2', 'DNS Query', '.onion', 'Tor', 'Callback', 'Beaconing'],
  'Lateral Movement': ['SMB', 'WMI', 'PSEXEC', 'Pass-the-Hash'],
  'Exfiltration': ['Data Exfil', 'FTP Upload', 'DNS Exfil', 'HTTPS Out', 'SSL Traffic'],
}

function getAttackPhase(alert) {
  const msg = alert.rule_message.toUpperCase()
  for (const [phase, keywords] of Object.entries(ATTACK_PHASES)) {
    if (keywords.some(kw => msg.includes(kw.toUpperCase()))) {
      return phase
    }
  }
  return 'Unknown'
}

function temporallyCluster(alerts, windowMinutes = 10) {
  if (alerts.length === 0) return []
  
  const sorted = [...alerts].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
  const clusters = []
  let current = [sorted[0]]
  let clusterStart = new Date(sorted[0].timestamp)

  for (let i = 1; i < sorted.length; i++) {
    const ts = new Date(sorted[i].timestamp)
    const elapsed = (ts - clusterStart) / (1000 * 60)  // minutes
    
    if (elapsed <= windowMinutes) {
      current.push(sorted[i])
    } else {
      clusters.push(current)
      current = [sorted[i]]
      clusterStart = ts
    }
  }
  if (current.length > 0) clusters.push(current)
  return clusters
}

function getConnectionPattern(alerts) {
  const conns = alerts.reduce((acc, a) => {
    const key = `${a.src_ip}:${a.dst_ip}`
    if (!acc[key]) acc[key] = { src_ip: a.src_ip, dst_ip: a.dst_ip, alerts: [] }
    acc[key].alerts.push(a)
    return acc
  }, {})
  return Object.values(conns)
}

function detectAttackProgression(alerts) {
  // Group by destination host, look for temporal progression of tactics
  const byDest = alerts.reduce((acc, a) => {
    if (!acc[a.dst_ip]) acc[a.dst_ip] = []
    acc[a.dst_ip].push(a)
    return acc
  }, {})

  let maxProgression = 0
  for (const destAlerts of Object.values(byDest)) {
    const sorted = [...destAlerts].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
    const phases = sorted.map(getAttackPhase)
    
    // Count unique phase transitions
    const uniquePhases = [...new Set(phases)]
    maxProgression = Math.max(maxProgression, uniquePhases.length)
  }
  return maxProgression
}

export function correlateIncidents(alerts, triageMap) {
  // Step 1: Temporal clustering
  const clusters = temporallyCluster(alerts, 15)
  
  const incidents = clusters.map((clusterAlerts, idx) => {
    const sortedAlerts = [...clusterAlerts].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
    const earliestTime = sortedAlerts[0].timestamp
    const latestTime = sortedAlerts[sortedAlerts.length - 1].timestamp

    // Identify unique src/dst pairs
    const conns = getConnectionPattern(clusterAlerts)
    const srcIPs = [...new Set(clusterAlerts.map(a => a.src_ip))]
    const dstIPs = [...new Set(clusterAlerts.map(a => a.dst_ip))]

    // Attack progression depth
    const progressionDepth = detectAttackProgression(clusterAlerts)

    // Determine severity — highest triage score in cluster
    const maxSeverity = Math.max(...clusterAlerts.map(a => triageMap[a.id]?.severity_score ?? 0))
    const severityLevel = maxSeverity >= 8 ? 'CRITICAL' : maxSeverity >= 6 ? 'HIGH' : maxSeverity >= 4 ? 'MEDIUM' : 'LOW'

    // Find dominant phase
    const phases = clusterAlerts.map(getAttackPhase)
    const phaseCounts = phases.reduce((acc, p) => {
      acc[p] = (acc[p] ?? 0) + 1
      return acc
    }, {})
    const dominantPhase = Object.entries(phaseCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'Unknown'

    // Generate incident ID
    const date = new Date(earliestTime).toISOString().slice(0, 10).replace(/-/g, '')
    const incidentId = `COR-${date}-${String(idx + 1).padStart(3, '0')}`

    // Short description
    const shortName = `${dominantPhase} Activity from ${srcIPs.join(', ')} to ${dstIPs.join(', ')}`

    return {
      incidentId,
      shortName,
      earliestTime,
      latestTime,
      srcIPs,
      dstIPs,
      alerts: sortedAlerts,
      conns,
      progressionDepth,
      maxSeverity,
      severityLevel,
      dominantPhase,
      phaseCounts,
    }
  })

  return incidents.sort((a, b) => new Date(b.earliestTime) - new Date(a.earliestTime))
}

export function generateIncidentReport(incident, triageMap) {
  const { incidentId, shortName, srcIPs, dstIPs, alerts, progressionDepth, severityLevel, dominantPhase } = incident

  // Timeline table
  let timelineTable = `| Timestamp (UTC) | Source IP:Port | Destination IP:Port | SID | Alert Message | Phase | Severity |\n`
  timelineTable += `|:---|:---|:---|:---|:---|:---|---|\n`
  
  for (const alert of alerts) {
    const t = triageMap[alert.id]
    const severity = t?.severity_score ?? '?'
    const phase = Object.entries(ATTACK_PHASES).find(([p, kws]) => 
      kws.some(kw => alert.rule_message.toUpperCase().includes(kw.toUpperCase()))
    )?.[0] ?? 'Unknown'
    const timestamp = new Date(alert.timestamp).toISOString().slice(0, 19).replace('T', ' ')
    const srcPort = alert.src_port ? `:${alert.src_port}` : ''
    const dstPort = alert.dst_port ? `:${alert.dst_port}` : ''
    
    timelineTable += `| ${timestamp} | ${alert.src_ip}${srcPort} | ${alert.dst_ip}${dstPort} | ${alert.sid} | ${alert.rule_message} | ${phase} | ${severity}/10 |\n`
  }

  // MITRE mapping table
  let mitreTable = `| Tactic | Technique ID | Technique Name | Associated SIDs | Justification |\n`
  mitreTable += `|:---|:---|:---|:---|---|\n`
  
  const techniqueMap = {}
  for (const alert of alerts) {
    const t = triageMap[alert.id]
    if (t?.mitre_tactic && t?.mitre_technique) {
      const key = `${t.mitre_tactic}|${t.mitre_technique}`
      if (!techniqueMap[key]) {
        techniqueMap[key] = { tactic: t.mitre_tactic, technique: t.mitre_technique, sids: [], justifications: [] }
      }
      techniqueMap[key].sids.push(alert.sid)
      techniqueMap[key].justifications.push(t.severity_justification)
    }
  }

  for (const { tactic, technique, sids, justifications } of Object.values(techniqueMap)) {
    // Extract T-number from technique string
    const match = technique.match(/\(T\d+\)/)
    const techId = match ? match[0].slice(1, -1) : 'T0000'
    const techName = technique.replace(/\s*\(T\d+\)\s*/, '').trim()
    mitreTable += `| ${tactic} | ${techId} | ${techName} | ${sids.join(', ')} | ${justifications[0]} |\n`
  }

  // Executive summary
  const summary = `An external threat actor conducted ${dominantPhase.toLowerCase()} activity. Temporal clustering detected ${alerts.length} alert(s) over ${progressionDepth} distinct attack phase(s), with progression depth suggesting a ${severityLevel.toLowerCase()}-severity campaign.`

  // Recommendations
  const recommendations = `
- **Containment**: Block source IP(s) ${srcIPs.join(', ')} at perimeter firewall and review WAF rules.
- **Investigation**: Examine application and firewall logs on destination host(s) ${dstIPs.join(', ')} for evidence of successful intrusion.
- **Eradication**: Apply latest security patches and conduct endpoint security scan.`

  return `
# [${incidentId}] ${shortName}

## Executive Summary
- **Summary**: ${summary}
- **Consolidated Severity**: \`${severityLevel}\`
- **Attacked Host(s)**: ${dstIPs.join(', ')}
- **Attacking Host(s)**: ${srcIPs.join(', ')}

## Correlated Timeline of Events
${timelineTable}

## MITRE ATT&CK Mapping Matrix
${mitreTable}

## Analytical Assessment & Reconstructed Attack Path
The incident shows a progression from \`${dominantPhase}\` activity, with \`${progressionDepth}\` distinct attack phase(s) detected. The attack trajectory suggests the threat actor was attempting to \`${
  severityLevel === 'CRITICAL' ? 'establish persistence and exfiltrate sensitive data' :
  severityLevel === 'HIGH' ? 'gain initial access or lateral movement' :
  'conduct reconnaissance or probe defenses'
}\`. The IDS successfully logged all malicious traffic; further investigation is required to determine if the attacks succeeded in breaching the target.

## Recommended Remediation Actions
${recommendations}
`
}
