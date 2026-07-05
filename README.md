# 🛡️ SOC Triage Agent

AI-powered SOC analyst for Snort IDS alerts. Paste in an alert, get back a triage in seconds — severity, attack classification, recommended action, and false positive likelihood — using Anthropic model.

## Stack

- **Backend:** Node.js + Express (port 3001)
- **Frontend:** React + Vite (port 5173)
- **AI:** Anthropic Claude (claude-opus-4-5)
- **Data:** Sample Snort alert logs in `/data/snort_alerts.json`

## Setup

### 1. Add your API key

Edit `.env`:
```
ANTHROPIC_API_KEY=sk-ant-...
```

### 2. Install dependencies

```bash
npm run install:all
```

### 3. Run dev servers (both concurrently)

```bash
npm run dev
```

- API: http://localhost:3001
- UI: http://localhost:5173

## API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/alerts` | Load sample Snort alerts from `/data/snort_alerts.json` |
| POST | `/api/triage` | Triage a single alert with Claude |
| POST | `/api/triage-bulk` | Triage all alerts at once |

### POST `/api/triage`
```json
{ "alert": { ...snort alert object... } }
```

### POST `/api/triage-bulk`
```json
{ "alerts": [ ...array of snort alert objects... ] }
```

## Adding Real Alerts

Replace or extend `/data/snort_alerts.json` with real Snort output. Each alert object should include:

```json
{
  "id": "alert-xxx",
  "timestamp": "2026-07-05T08:00:00Z",
  "sid": 1000001,
  "rule_message": "ET SCAN ...",
  "priority": 1,
  "protocol": "TCP",
  "src_ip": "1.2.3.4",
  "src_port": 12345,
  "dst_ip": "10.0.0.1",
  "dst_port": 443,
  "payload_snippet": "optional raw snippet",
  "flags": "SYN",
  "count": 1
}
```

## Project Structure

```
soc-triage-agent/
├── .env                  # API key (gitignored)
├── .env.example          # Template
├── package.json          # Root scripts (concurrently)
├── server/
│   ├── index.js          # Express API + Claude integration
│   └── package.json
├── client/
│   ├── src/
│   │   ├── App.jsx       # Main React component
│   │   └── App.css       # Dark SOC-themed styles
│   └── package.json
└── data/
    └── snort_alerts.json # 8 sample Snort alerts

```
Sample alerts triage from Snort IDS
<img width="1897" height="883" alt="Alerts" src="https://github.com/user-attachments/assets/72f0cfc8-aed9-441d-8977-9c91805de885" />

Sample Incident summarization by alerts gathering and correlation:
<img width="1897" height="883" alt="Incident" src="https://github.com/user-attachments/assets/df2d1206-2b88-4fd2-a4c4-19f183accccd" />

Incident details (Summary, Timeline, MITRE ATT&CK mapping)
<img width="1897" height="883" alt="image" src="https://github.com/user-attachments/assets/3660efc0-292e-41e9-b18c-e4860f988ac2" />

Analytical assessment and Recommended actions:
<img width="1906" height="357" alt="image" src="https://github.com/user-attachments/assets/706b416c-b80a-433e-9634-77dd6f5ca8cf" />




