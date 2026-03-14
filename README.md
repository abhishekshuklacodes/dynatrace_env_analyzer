# Dynatrace Multi-Environment Analyzer v4.0

> Comprehensive audit, gap analysis, noise detection, and Smartscape topology diagrams across multiple Dynatrace environments — with deprecated API detection, Davis AI summary, interactive HTML dashboard, and PDF/JSON export.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Dynatrace API](https://img.shields.io/badge/Dynatrace-API%20v2-6F2DA8)
![License](https://img.shields.io/badge/License-MIT-green)

---

## What's New in v4.0

| Feature | Source | Description |
|---------|--------|-------------|
| **Data Ingestion Metrics** | v3.2 merge | Log, metric, DDU volumes via Metrics v2 API |
| **Noise Analysis** | v3.2 merge | Recurring problem detection with top noise sources |
| **Anomaly Detection Audit** | v3.2 merge | Services, RUM, infra, disk, DB anomaly settings |
| **Davis AI Summary** | v3.2 merge | Per-environment Davis AI problem digest |
| **HTML Dashboard** | v3.2 merge | Interactive Plotly charts, tabbed navigation |
| **JSON Export** | New | Raw data for n8n/ServiceNow/JIRA automation |
| **SSL Toggle** | v3.2 merge | `verify_ssl: false` for Managed behind proxy |
| **Zero SDK** | Refactor | Pure `requests` — no `dynatrace` SDK dependency |
| **Pagination Fix** | Bugfix | Correct nextPageKey handling per Dynatrace docs |
| **Expanded Deprecated Probes** | New | Config v1 autoTags, alertingProfiles, notifications, MZ |

---

## Output

The analyzer produces **three outputs**:

```
dt_reports/
├── dt_analysis_20260315_143022.pdf     # 13-section PDF report
├── dashboard_v4.0.html                  # Interactive HTML dashboard
├── dt_audit_20260315_143022.json        # Raw JSON for automation
├── smartscape_PROD.png                  # Topology diagram
├── smartscape_NON-PROD.png
└── smartscape_DR.png
```

### PDF Report (13 sections)
1. Executive Summary
2. Entity Counts
3. Smartscape Topology Diagrams
4. Deprecated API Audit (with full reference table)
5. Problems, Noise Sources & Davis AI Summary
6. Alerting & Anomaly Detection Config
7. SLO Assessment
8. Data Ingestion (30d)
9. Infrastructure (ActiveGates)
10. Governance (MZ, Tags, Network Zones, Synthetic, Extensions)
11. Gap Analysis — All Findings
12. Recommendations — Prioritized
13. Appendix — Token Scopes

### HTML Dashboard (9 tabs)
Overview | Davis AI | Noise Analysis | Alerts Config | Data Ingestion | Gap Matrix | Recommendations | Smartscape

---

## Quick Start

```bash
git clone https://github.com/abhishekshuklacodes/dynatrace_env_analyzer.git
cd dynatrace_env_analyzer
pip install -r requirements.txt
cp config.yaml.template config.yaml
# Edit config.yaml with your environment URLs and tokens
python dt_env_analyzer.py --config config.yaml
```

### Required Token Scopes

| Scope | Purpose |
|-------|---------|
| `entities.read` | Entity topology & relationships |
| `metrics.read` | Metrics metadata + ingestion volumes |
| `problems.read` | Problem feed analysis |
| `settings.read` | Settings 2.0 (alerting, MZ, tags, anomaly) |
| `events.read` | Event feed |
| `activeGates.read` | ActiveGate inventory |
| `slo.read` | SLO evaluation |
| `oneAgents.read` | OneAgent inventory |
| `auditLogs.read` | Config audit trail |
| `networkZones.read` | Network zone config |
| `extensions.read` | Extensions 2.0 inventory |

### CLI Options

```bash
python dt_env_analyzer.py --config config.yaml              # Full run (PDF + HTML + JSON)
python dt_env_analyzer.py --config config.yaml --output r.pdf  # Custom PDF path
python dt_env_analyzer.py --config config.yaml --skip-diagrams # No Graphviz needed
python dt_env_analyzer.py --config config.yaml --lookback 90   # 90-day lookback
python dt_env_analyzer.py --generate-template                  # Create config template
python dt_env_analyzer.py -v                                   # Debug logging
```

---

## Architecture

```
config.yaml ──► DynatraceClient ──► Dynatrace API v2
                (pagination,         ├── /api/v2/entities
                 retry,              ├── /api/v2/problems
                 rate-limit)         ├── /api/v2/settings/objects
                      │              ├── /api/v2/metrics/query
                      ▼              ├── /api/v2/slo
               EnvironmentAnalyzer   ├── /api/v2/activeGates
               ├── Entity topology   ├── /api/v2/oneAgents
               ├── Problem + noise   ├── /api/v2/extensions
               ├── Ingestion metrics └── /api/v1/* (deprecated probes)
               ├── Anomaly detection
               ├── Deprecated probes
               └── Gap analysis
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
    PDFReport    HTMLDashboard   JSON Export
    (reportlab)  (Plotly/BS5)   (raw data)
          │
    SmartscapeDiagram
    (Graphviz PNG)
```

---

## Deprecated API Coverage

| Deprecated | Replacement | EOL |
|-----------|-------------|-----|
| Timeseries v1 | Metrics v2 | End of 2025 |
| Topology & Smartscape | Entities v2 | TBD |
| Problems v1 | Problems v2 | TBD |
| Events v1 | Events v2 | TBD |
| Log Monitoring v2 search/export | Grail Query API | End of 2027 |
| Config v1 (autoTags, alerting, notifications, MZ) | Settings 2.0 | TBD |
| Maintenance Windows (env + config) | Settings 2.0 | TBD |
| Credential Vault (config) | Credential Vault v2 | TBD |
| Tokens v1 | Access Tokens v2 | TBD |

---

## Security

- `config.yaml` is in `.gitignore` — **never commit tokens**
- Auth via `Authorization: Api-Token` header (not URL params)
- All calls over HTTPS
- `verify_ssl: false` available for Managed environments behind corporate proxy

---

## License

MIT — see [LICENSE](LICENSE)
