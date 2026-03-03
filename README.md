# UIP - Unified Incident Management Platform

A centralized incident management platform built for Tucows Domains SRE operations. UIP aggregates alerts from monitoring systems (Zabbix), enriches them with AI-powered analysis using a local LLM, and presents actionable intelligence through a purpose-built SRE command center.

## Problem

SRE teams deal with high volumes of alerts from multiple monitoring sources. Raw alerts lack context — a "High CPU Utilization" alert doesn't tell you how high, what's affected, or whether it's correlated with other issues. SREs waste time triaging noise, manually correlating events, and context-switching between tools.

## Solution

UIP provides a single pane of glass that:

- **Aggregates alerts** from Zabbix (with support for additional sources like Prometheus, Grafana, Datadog)
- **Enriches with AI analysis** — a local LLM (Ollama/Qwen) assesses severity, identifies root causes, suggests remediation, scores noise likelihood, and detects duplicates/correlations
- **Includes real metric values** — alerts show actual measurements (e.g., "CPU utilization: 92.5%") not just titles
- **Learns from SRE feedback** — analysts can rate AI assessments and provide corrections, which feed back into future analysis
- **Applies Google SRE principles** — the AI analyzes alerts through the lens of the Four Golden Signals, user impact, symptoms vs causes, and error budget thinking

## Architecture

```
Zabbix Production
    |
    v
[Zabbix Poller] --> [Keep API] --> [PostgreSQL]
                         |
                         v
                  [Alert Enricher] <--> [Ollama LLM]
                         |
                         v
                  [Keep API] (enriched alerts)
                         |
                         v
                  [SRE Frontend] <-- [Nginx Reverse Proxy] <-- SRE Users

                  [n8n] (workflow automation for Slack routing, escalation)
```

### Services (Docker Compose)

| Service | Purpose | Image |
|---------|---------|-------|
| **PostgreSQL** | Shared database for alerts, workflows | `postgres:16-alpine` |
| **Keep API** | Alert aggregation and storage backend | `keep-api:latest` |
| **Keep Frontend** | Admin UI for provider/integration management | `keep-ui:latest` |
| **Ollama** | Local LLM inference (no cloud API dependencies) | `ollama/ollama:latest` |
| **Alert Enricher** | AI-powered alert analysis and enrichment | `python:3.12-slim` |
| **Zabbix Poller** | Polls Zabbix for active problems, forwards to Keep | `python:3.12-slim` |
| **SRE Frontend** | Custom Next.js command center for SRE teams | Custom Dockerfile |
| **n8n** | Workflow automation (severity routing, Slack integration) | `n8n:latest` |
| **Nginx** | Reverse proxy, API gateway, landing page | `nginx:alpine` |

## SRE Frontend Features

### Command Center (`/portal/command-center`)
- Real-time dashboard with alert severity breakdown
- Interactive filtering by severity and alert source
- Active alerts table with AI summaries, noise scores, and metric values
- Auto-refresh every 30 seconds

### Alert Explorer (`/portal/alerts`)
- Full alert list with search, sort, and advanced filtering
- Status filters (Active, Resolved, All)
- Severity and noise score indicators

### Alert Detail (`/portal/alerts/[fingerprint]`)
- Complete AI analysis: assessed severity, likely cause, remediation steps, impact scope
- Deduplication assessment (DUPLICATE, CORRELATED, or UNIQUE)
- Real metric values from Zabbix items
- SRE feedback panel — rate AI accuracy, provide corrections, add context
- Feedback is ingested by the enricher and applied to future similar alerts

## AI Enrichment

Each alert is analyzed by a local LLM with context including:
- Alert details and metric values
- Service dependency map (DNS, WHOIS, EPP, billing, databases, etc.)
- Similar recent alerts for correlation
- Historical SRE feedback and corrections

The enrichment produces:
- **Assessed Severity**: Independent severity rating based on actual impact
- **Likely Cause**: Root cause analysis
- **Remediation**: Triage and action steps
- **Impact Scope**: Affected services and users
- **Noise Score** (1-10): How likely this is actionable vs noise
- **Dedup Assessment**: Whether this duplicates or correlates with other alerts
- **Summary**: One-line plain English description

## Project Structure

```
deploy/
  docker-compose.yml          # Full stack orchestration
  nginx-default.conf          # Reverse proxy + landing page
  poller.py                   # Zabbix -> Keep alert forwarder
  enricher.py                 # AI enrichment engine
  sre-frontend/
    src/app/
      command-center/page.tsx  # Dashboard
      alerts/page.tsx          # Alert list
      alerts/[fingerprint]/    # Alert detail + feedback
      layout.tsx               # Navigation shell
    src/lib/
      types.ts                 # TypeScript interfaces
      keep-api.ts              # API client functions
```

## Deployment

The platform runs on a single server via Docker Compose. Environment variables are configured in a `.env` file (not committed) with credentials for Zabbix, PostgreSQL, Keep API, and n8n.

```bash
# On the deployment server
cd /home/fash/uip
docker compose up -d
```

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `POSTGRES_USER` | PostgreSQL username |
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `KEEP_API_KEY` | API key for Keep alert platform |
| `ZABBIX_URL` | Zabbix API endpoint |
| `ZABBIX_USER` | Zabbix API username |
| `ZABBIX_PASS` | Zabbix API password |
| `OLLAMA_MODEL` | LLM model name (default: `qwen2.5:7b`) |
| `N8N_ENCRYPTION_KEY` | n8n encryption key |
| `NEXTAUTH_SECRET` | NextAuth session secret |

## Development

The SRE frontend is a Next.js 14 application with Tailwind CSS:

```bash
cd deploy/sre-frontend
npm install
npm run dev
```

The Python services (`poller.py`, `enricher.py`) are single-file scripts with no external dependencies beyond the Python standard library.
