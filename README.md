# Dynatrace Multi-Environment Analyzer

> Comprehensive audit, gap analysis, and Smartscape-like topology diagrams across multiple Dynatrace environments — with full deprecated API detection aligned to Dynatrace's latest v1→v2 migration timeline.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Dynatrace API](https://img.shields.io/badge/Dynatrace-API%20v2-6F2DA8)
![License](https://img.shields.io/badge/License-MIT-green)

---

## What It Does

This script connects to **multiple Dynatrace environments** (PROD, NON-PROD, DR, etc.) via the **Environment API v2** and performs a comprehensive analysis covering:

| Domain | Details |
|--------|---------|
| **Entity Topology** | Hosts, Services, Process Groups, Applications, K8s Clusters with full relationship mapping |
| **Smartscape Diagrams** | Auto-generated Graphviz topology diagrams per environment (PNG) |
| **Deprecated API Audit** | Probes v1 endpoints to detect live usage; maps all deprecated APIs with EOL dates |
| **Problem Analysis** | 30-day problem feed — severity breakdown, open count, noise detection |
| **Alerting Config** | Alerting profiles, notification rules, maintenance windows via Settings 2.0 |
| **SLO Assessment** | Evaluates all SLOs and flags breaching targets |
| **Infrastructure Health** | ActiveGate versions/modules, OneAgent update status |
| **Governance** | Management zones, auto-tag rules, network zones |
| **Observability Gaps** | Missing RUM, no synthetic monitors, no MZ, untagged entities |
| **Prioritized Recommendations** | P0→P3 action plan with effort estimates |

**Output:** A multi-section **PDF report** + **PNG topology diagrams** per environment.

---

## Deprecated API Coverage

The analyzer tracks all major Dynatrace API deprecations including:

| Deprecated | Replacement | EOL |
|-----------|-------------|-----|
| Timeseries API v1 | Metrics API v2 | End of 2025 |
| Topology & Smartscape API | Monitored Entities API v2 | TBD |
| Problems API v1 | Problems API v2 | TBD |
| Events API v1 | Events API v2 | TBD |
| Log Monitoring v2 (search/export) | Grail Query API | End of 2027 |
| Config v1 (autoTags, alertingProfiles, notifications, managementZones) | Settings 2.0 API | TBD |
| Maintenance Windows (env + config) | Settings 2.0 | TBD |
| Credential Vault (config) | Credential Vault (env v2) | TBD |
| Tokens API v1 | Access Tokens API v2 | TBD |

---

## Quick Start

### Prerequisites

- Python 3.9+
- Graphviz installed (`apt install graphviz` / `brew install graphviz`)
- API tokens for each Dynatrace environment

### Install

```bash
git clone https://github.com/<your-username>/dynatrace-env-analyzer.git
cd dynatrace-env-analyzer
pip install -r requirements.txt
```

### Configure

```bash
cp config.yaml.template config.yaml
# Edit config.yaml with your environment URLs and tokens
```

### Required Token Scopes

Create an API token in each environment (**Access Tokens → Generate new token**) with these scopes:

| Scope | Purpose |
|-------|---------|
| `entities.read` | Entity topology & relationships |
| `metrics.read` | Metrics metadata |
| `problems.read` | Problem feed analysis |
| `settings.read` | Settings 2.0 (alerting, MZ, tags) |
| `events.read` | Event feed |
| `activeGates.read` | ActiveGate inventory |
| `slo.read` | SLO evaluation |
| `oneAgents.read` | OneAgent inventory |
| `auditLogs.read` | Config audit trail |
| `networkZones.read` | Network zone config |
| `extensions.read` | Extensions 2.0 inventory |

### Run

```bash
# Full analysis with PDF report + diagrams
python dt_env_analyzer.py --config config.yaml

# Custom output path
python dt_env_analyzer.py --config config.yaml --output my_report.pdf

# Skip diagram generation (no Graphviz needed)
python dt_env_analyzer.py --config config.yaml --skip-diagrams

# Custom lookback period
python dt_env_analyzer.py --config config.yaml --lookback 90

# Debug mode
python dt_env_analyzer.py --config config.yaml -v
```

---

## Output Structure

```
dt_reports/
├── dt_analysis_20260314_143022.pdf     # Full PDF report
├── smartscape_PROD.png                  # Topology diagram — PROD
├── smartscape_NON-PROD.png              # Topology diagram — NON-PROD
└── smartscape_DR.png                    # Topology diagram — DR
```

### PDF Report Sections

1. Executive Summary
2. Environment Overview & Entity Counts
3. Smartscape Topology Diagrams
4. Deprecated API Audit
5. Problem & Event Analysis
6. Alerting & Notification Configuration
7. SLO Assessment
8. Infrastructure Health (ActiveGates & OneAgents)
9. Governance (Management Zones, Auto-Tags, Network Zones)
10. Gap Analysis — Consolidated Findings
11. Recommendations — Prioritized Action Plan
12. Appendix — Token Scopes & Deprecated API Reference

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   config.yaml   │────▶│  DynatraceClient │────▶│ Environment API  │
│  (3 environments│     │  (pagination,     │     │ v2 endpoints     │
│   + tokens)     │     │   retry, rate     │     │                  │
└─────────────────┘     │   limiting)       │     └──────────────────┘
                        └────────┬─────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  EnvironmentAnalyzer    │
                    │  - Entity topology      │
                    │  - Problem analysis     │
                    │  - Alerting audit       │
                    │  - SLO evaluation       │
                    │  - Deprecated API probe │
                    │  - Gap analysis         │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                   ▼
    ┌─────────────────┐ ┌──────────────┐  ┌─────────────────┐
    │ SmartscapeDiagram│ │ReportGenerator│  │  Console Output │
    │ (Graphviz PNG)   │ │ (PDF report) │  │  (Summary)      │
    └─────────────────┘ └──────────────┘  └─────────────────┘
```

---

## Security Notes

- `config.yaml` is in `.gitignore` — **never commit tokens**
- Tokens are passed via `Authorization: Api-Token` header (not URL params)
- All API calls use HTTPS
- Rate limiting built in to avoid throttling

---

## Contributing

PRs welcome. Please ensure any new API endpoints follow the v2 pattern and include proper deprecation mapping.

---

## License

MIT — see [LICENSE](LICENSE)
