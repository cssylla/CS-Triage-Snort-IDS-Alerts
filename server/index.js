require('dotenv').config({ path: '../.env' });
const express = require('express');
const cors = require('cors');
const Anthropic = require('@anthropic-ai/sdk');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

app.use(cors());
app.use(express.json());

// GET /api/alerts — return sample Snort alert logs
app.get('/api/alerts', (req, res) => {
  try {
    const dataPath = path.join(__dirname, '../data/snort_alerts.json');
    const alerts = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    res.json({ success: true, alerts });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to load alert data' });
  }
});

// POST /api/triage — Tier-1 SOC triage via Claude, returns structured JSON
app.post('/api/triage', async (req, res) => {
  const { alert } = req.body;

  if (!alert || typeof alert !== 'object') {
    return res.status(400).json({ success: false, error: 'Missing or invalid alert payload' });
  }

  const systemPrompt = `You are a SOC Tier-1 analyst. You will receive a Snort IDS alert in JSON format.
Your task is to triage the alert and respond with ONLY a valid JSON object — no prose, no markdown, no code fences.

The JSON must contain exactly these fields:
- mitre_tactic (string): The MITRE ATT&CK tactic name (e.g., "Reconnaissance", "Execution", "Command and Control")
- mitre_technique (string): The technique name plus T-number in parentheses (e.g., "Network Service Scanning (T1046)")
- severity_score (integer 1–10): 1 = negligible, 10 = critical. Base this on exploit reliability, blast radius, and asset exposure.
- severity_justification (string): One sentence explaining the score.
- false_positive_likelihood (string): Must be exactly one of: "low", "medium", or "high"
- recommended_action (string): Immediate, specific action for a Tier-1 analyst (e.g., isolate host, block IP, escalate to Tier-2).
- incident_summary (string): 2–3 sentences written in NIST SP 800-61 style — describe what was observed, what it likely indicates, and the potential impact.

Rules:
- Output ONLY the raw JSON object. No explanation outside the JSON.
- Do not wrap the JSON in markdown code fences.
- All string values must be properly escaped.
- The JSON must be parseable with JSON.parse() with no preprocessing.`;

  const userMessage = `Triage this Snort alert:\n\n${JSON.stringify(alert, null, 2)}`;

  try {
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1024,
      system: systemPrompt,
      messages: [{ role: 'user', content: userMessage }],
    });

    const raw = message.content[0].text.trim();

    // Parse and validate the JSON response
    let triage;
    try {
      triage = JSON.parse(raw);
    } catch (parseErr) {
      // Attempt to extract JSON object if model added any surrounding text
      const match = raw.match(/\{[\s\S]*\}/);
      if (match) {
        triage = JSON.parse(match[0]);
      } else {
        console.error('Non-JSON response from Claude:', raw);
        return res.status(502).json({ success: false, error: 'Model returned non-JSON response', raw });
      }
    }

    // Validate required fields
    const requiredFields = [
      'mitre_tactic',
      'mitre_technique',
      'severity_score',
      'severity_justification',
      'false_positive_likelihood',
      'recommended_action',
      'incident_summary',
    ];
    const missing = requiredFields.filter(f => !(f in triage));
    if (missing.length > 0) {
      return res.status(502).json({
        success: false,
        error: `Model response missing required fields: ${missing.join(', ')}`,
        partial: triage,
      });
    }

    // Coerce and validate severity_score
    triage.severity_score = Number(triage.severity_score);
    if (isNaN(triage.severity_score) || triage.severity_score < 1 || triage.severity_score > 10) {
      return res.status(502).json({ success: false, error: 'Invalid severity_score — must be 1–10', partial: triage });
    }

    // Normalise false_positive_likelihood
    triage.false_positive_likelihood = String(triage.false_positive_likelihood).toLowerCase();
    if (!['low', 'medium', 'high'].includes(triage.false_positive_likelihood)) {
      triage.false_positive_likelihood = 'medium'; // safe default
    }

    res.json({ success: true, alert_id: alert.id ?? null, triage });
  } catch (err) {
    console.error('Anthropic API error:', err.message);
    res.status(500).json({ success: false, error: 'AI triage failed: ' + err.message });
  }
});

// POST /api/triage-bulk — triage multiple alerts at once
app.post('/api/triage-bulk', async (req, res) => {
  const { alerts } = req.body;

  if (!alerts || !Array.isArray(alerts) || alerts.length === 0) {
    return res.status(400).json({ success: false, error: 'Missing or invalid alerts array' });
  }

  const systemPrompt = `You are an expert SOC analyst. You will receive multiple Snort IDS alerts.
Triage each one with:
- Severity (Critical/High/Medium/Low/Info)
- Attack type
- One-line risk summary
- Recommended action
- False positive likelihood

Format your response as a JSON array with fields: id, severity, attack_type, risk_summary, recommended_action, false_positive_likelihood.`;

  const userMessage = `Triage the following ${alerts.length} Snort alerts:\n\n${JSON.stringify(alerts, null, 2)}`;

  try {
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 4096,
      system: systemPrompt,
      messages: [{ role: 'user', content: userMessage }],
    });

    const raw = message.content[0].text;
    // Try to extract JSON from the response
    const jsonMatch = raw.match(/\[[\s\S]*\]/);
    const results = jsonMatch ? JSON.parse(jsonMatch[0]) : raw;

    res.json({ success: true, results });
  } catch (err) {
    console.error('Anthropic API error:', err.message);
    res.status(500).json({ success: false, error: 'Bulk triage failed: ' + err.message });
  }
});

app.listen(PORT, () => {
  console.log(`🛡️  SOC Triage Agent API running on http://localhost:${PORT}`);
});
