#!/usr/bin/env python3
"""
Dynatrace Multi-Environment Comprehensive Analyzer v4.0
========================================================
Author  : Abhi (Observability Operations)
Purpose : Audit multiple Dynatrace environments via API v2, detect deprecated API
          usage, generate Smartscape-like architecture diagrams, identify gaps,
          and produce consolidated PDF + interactive HTML dashboard + JSON export.

Refactored from:
  - dt_env_analyzer.py  (v3.0) — robust API client, pagination, PDF report
  - main_pdf.py         (v3.2) — data ingestion metrics, noise analysis, HTML dashboard

Key improvements in v4.0:
  - Merged data ingestion (log, metric, DDU) analysis from v3.2
  - Added noise-source detection (recurring problem titles) from v3.2
  - Added anomaly detection settings audit from v3.2
  - Added Davis AI summary per environment from v3.2
  - Dual output: PDF report + interactive HTML dashboard with Plotly charts
  - JSON raw data export for downstream tooling (n8n, ServiceNow, etc.)
  - SSL verification toggle per environment (for Managed behind corporate proxy)
  - Removed dependency on `dynatrace` SDK — pure requests-based (zero SDK deps)
  - Fixed: pagination nextPageKey handling per Dynatrace docs
  - Fixed: Smartscape diagram variable scoping bug on failure
  - Added: Anomaly detection schemas audit (services, RUM, infra)
  - Added: Cross-environment gap comparison matrix

Required Token Scopes (per environment):
  - entities.read           — Entity topology & relationships
  - metrics.read            — Metrics metadata + data ingestion volumes
  - problems.read           — Problem feed analysis
  - settings.read           — Settings 2.0 (alerting, MZ, tags, anomaly detection)
  - events.read             — Event feed
  - activeGates.read        — ActiveGate inventory
  - slo.read                — SLO evaluation
  - oneAgents.read          — OneAgent inventory
  - auditLogs.read          — Config audit trail
  - networkZones.read       — Network zone config
  - extensions.read         — Extensions 2.0 inventory

Usage:
  python dt_env_analyzer.py --config config.yaml
  python dt_env_analyzer.py --config config.yaml --output report.pdf --html
  python dt_env_analyzer.py --generate-template
"""

import argparse
import json
import logging
import os
import sys
import time
import traceback
import urllib3
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
import requests
import graphviz

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable,
)
from reportlab.lib.enums import TA_CENTER

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("dt-analyzer")


# ═══════════════════════════════════════════════════════════════════
#  CONSTANTS & REFERENCE DATA
# ═══════════════════════════════════════════════════════════════════

DEPRECATED_API_MAP = {
    "/api/v1/timeseries": {"replacement": "/api/v2/metrics/query", "deprecated_since": "SaaS 1.305 / Managed 1.316", "eol": "End of 2025", "severity": "CRITICAL"},
    "/api/v1/entity": {"replacement": "/api/v2/entities", "deprecated_since": "1.263", "eol": "TBD", "severity": "HIGH"},
    "/api/v1/entity/infrastructure/hosts": {"replacement": "/api/v2/entities?entitySelector=type(HOST)", "deprecated_since": "1.263", "eol": "TBD", "severity": "HIGH"},
    "/api/v1/entity/infrastructure/processes": {"replacement": "/api/v2/entities?entitySelector=type(PROCESS_GROUP_INSTANCE)", "deprecated_since": "1.263", "eol": "TBD", "severity": "HIGH"},
    "/api/v1/entity/infrastructure/process-groups": {"replacement": "/api/v2/entities?entitySelector=type(PROCESS_GROUP)", "deprecated_since": "1.263", "eol": "TBD", "severity": "HIGH"},
    "/api/v1/entity/services": {"replacement": "/api/v2/entities?entitySelector=type(SERVICE)", "deprecated_since": "1.263", "eol": "TBD", "severity": "HIGH"},
    "/api/v1/entity/applications": {"replacement": "/api/v2/entities?entitySelector=type(APPLICATION)", "deprecated_since": "1.263", "eol": "TBD", "severity": "HIGH"},
    "/api/v1/problem": {"replacement": "/api/v2/problems", "deprecated_since": "SaaS 1.243 / Managed 1.244", "eol": "TBD", "severity": "HIGH"},
    "/api/v1/events": {"replacement": "/api/v2/events", "deprecated_since": "SaaS 1.243 / Managed 1.244", "eol": "TBD", "severity": "HIGH"},
    "/api/v1/tokens": {"replacement": "/api/v2/apiTokens", "deprecated_since": "1.252", "eol": "TBD", "severity": "MEDIUM"},
    "/api/v1/maintenance-window": {"replacement": "/api/v2/settings (builtin:alerting.maintenance-window)", "deprecated_since": "SaaS 1.173 / Managed 1.174", "eol": "TBD", "severity": "MEDIUM"},
    "/api/config/v1/maintenanceWindows": {"replacement": "/api/v2/settings (builtin:alerting.maintenance-window)", "deprecated_since": "SaaS 1.173 / Managed 1.174", "eol": "TBD", "severity": "MEDIUM"},
    "/api/config/v1/credentials": {"replacement": "/api/v2/credentials", "deprecated_since": "1.252", "eol": "TBD", "severity": "MEDIUM"},
    "/api/v2/logs/search": {"replacement": "Grail Query API", "deprecated_since": "SaaS 1.280 / Managed 1.284", "eol": "End of 2027", "severity": "MEDIUM"},
    "/api/v2/logs/export": {"replacement": "Grail Query API", "deprecated_since": "SaaS 1.280 / Managed 1.284", "eol": "End of 2027", "severity": "MEDIUM"},
    "/api/v2/logs/aggregate": {"replacement": "Grail Query API", "deprecated_since": "SaaS 1.280 / Managed 1.284", "eol": "End of 2027", "severity": "MEDIUM"},
    "/api/config/v1/autoTags": {"replacement": "/api/v2/settings (builtin:tags.auto-tagging)", "deprecated_since": "Settings 2.0 migration", "eol": "TBD", "severity": "MEDIUM"},
    "/api/config/v1/alertingProfiles": {"replacement": "/api/v2/settings (builtin:alerting.profile)", "deprecated_since": "Settings 2.0 migration", "eol": "TBD", "severity": "MEDIUM"},
    "/api/config/v1/notifications": {"replacement": "/api/v2/settings (builtin:problem.notifications)", "deprecated_since": "Settings 2.0 migration", "eol": "TBD", "severity": "MEDIUM"},
    "/api/config/v1/managementZones": {"replacement": "/api/v2/settings (builtin:management-zones)", "deprecated_since": "Settings 2.0 migration", "eol": "TBD", "severity": "MEDIUM"},
    "/api/config/v1/requestAttributes": {"replacement": "/api/v2/settings (builtin:request-attributes)", "deprecated_since": "Settings 2.0 migration", "eol": "TBD", "severity": "LOW"},
}

SMARTSCAPE_ENTITY_TYPES = [
    "HOST", "PROCESS_GROUP", "PROCESS_GROUP_INSTANCE", "SERVICE",
    "APPLICATION", "HTTP_CHECK", "BROWSER_MONITOR", "SYNTHETIC_TEST",
    "KUBERNETES_CLUSTER", "CLOUD_APPLICATION", "CLOUD_APPLICATION_NAMESPACE",
]

INGESTION_METRICS = {
    "log_ingest_bytes": "builtin:billing.log_storage.total_volume",
    "metric_ingest_total": "builtin:billing.ddu.metrics.total",
    "ddu_total": "builtin:billing.ddu",
}

ANOMALY_SCHEMAS = [
    "builtin:anomaly-detection.infrastructure-hosts",
    "builtin:anomaly-detection.infrastructure-disks",
    "builtin:anomaly-detection.services",
    "builtin:anomaly-detection.rum-web",
    "builtin:anomaly-detection.databases",
]

DT_PURPLE, DT_BLUE, DT_GREEN, DT_RED, DT_ORANGE, DT_DARK = "#6F2DA8", "#1496FF", "#2AB06F", "#DC172A", "#FF6A00", "#1A1A2E"


# ═══════════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════════

DEFAULT_CONFIG_TEMPLATE = """# Dynatrace Multi-Environment Analyzer v4.0 — Configuration
environments:
  - name: "PROD"
    url: "https://abc12345.live.dynatrace.com"
    token: "dt0c01.XXXXXXXX.YYYYYYYYYYYYYYYY"
    type: "SaaS"
    verify_ssl: true

  - name: "NON-PROD"
    url: "https://def67890.live.dynatrace.com"
    token: "dt0c01.XXXXXXXX.YYYYYYYYYYYYYYYY"
    type: "SaaS"
    verify_ssl: true

  - name: "DR"
    url: "https://ghi11223.live.dynatrace.com"
    token: "dt0c01.XXXXXXXX.YYYYYYYYYYYYYYYY"
    type: "SaaS"
    verify_ssl: true

settings:
  timeout_seconds: 30
  max_retries: 3
  rate_limit_pause: 0.25
  lookback_days: 30
  output_dir: "./dt_reports"
  generate_html: true
  generate_json: true
"""


def load_config(config_path: str) -> dict:
    path = Path(config_path)
    if not path.exists():
        Path(config_path + ".template").write_text(DEFAULT_CONFIG_TEMPLATE)
        log.error(f"Config not found: {config_path} — template created.")
        sys.exit(1)
    with open(path) as f:
        cfg = yaml.safe_load(f)
    if not cfg.get("environments"):
        log.error("No environments in config."); sys.exit(1)
    for env in cfg["environments"]:
        for k in ("name", "url", "token"):
            if not env.get(k):
                log.error(f"Missing '{k}' in: {env}"); sys.exit(1)
        env["url"] = env["url"].rstrip("/")
        env.setdefault("type", "SaaS")
        env.setdefault("verify_ssl", True)
    if any(not e.get("verify_ssl", True) for e in cfg["environments"]):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return cfg


# ═══════════════════════════════════════════════════════════════════
#  DYNATRACE API CLIENT
# ═══════════════════════════════════════════════════════════════════

class DynatraceClient:
    """Pure-requests Dynatrace API v2 client. No SDK dependency."""

    def __init__(self, name, url, token, env_type="SaaS", verify_ssl=True,
                 timeout=30, max_retries=3, rate_pause=0.25):
        self.name, self.base_url, self.token = name, url, token
        self.env_type, self.verify_ssl = env_type, verify_ssl
        self.timeout, self.max_retries, self.rate_pause = timeout, max_retries, rate_pause
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Api-Token {token}",
                                      "Content-Type": "application/json", "Accept": "application/json"})
        self.session.verify = verify_ssl
        self._call_count = 0

    def _request(self, method, endpoint, params=None, json_body=None) -> Optional[dict]:
        url = f"{self.base_url}{endpoint}"
        for attempt in range(1, self.max_retries + 1):
            try:
                time.sleep(self.rate_pause)
                self._call_count += 1
                resp = self.session.request(method, url, params=params, json=json_body, timeout=self.timeout)
                if resp.status_code == 429:
                    wait = int(resp.headers.get("Retry-After", 5))
                    log.warning(f"[{self.name}] Rate limited on {endpoint}. Waiting {wait}s...")
                    time.sleep(wait); continue
                if resp.status_code in (401, 403):
                    log.warning(f"[{self.name}] {resp.status_code} on {endpoint}"); return None
                if resp.status_code == 404:
                    log.debug(f"[{self.name}] 404: {endpoint}"); return None
                resp.raise_for_status()
                return resp.json() if resp.text else {}
            except requests.exceptions.Timeout:
                log.warning(f"[{self.name}] Timeout {endpoint} ({attempt}/{self.max_retries})")
            except requests.exceptions.ConnectionError:
                log.warning(f"[{self.name}] ConnError {endpoint} ({attempt}/{self.max_retries})")
            except requests.exceptions.HTTPError as e:
                log.warning(f"[{self.name}] HTTP {e}"); return None
            except Exception as e:
                log.error(f"[{self.name}] Error on {endpoint}: {e}"); return None
        log.error(f"[{self.name}] Failed after {self.max_retries} retries: {endpoint}")
        return None

    def get(self, endpoint, params=None):
        return self._request("GET", endpoint, params=params)

    def get_paginated(self, endpoint, params=None, items_key=None) -> list:
        all_items, params = [], params or {}
        resp = self.get(endpoint, params)
        if not resp: return all_items
        if not items_key:
            for c in ("entities","metrics","records","problems","events","results",
                      "objects","activeGates","tokens","slo","extensions","monitors",
                      "items","networkZones","hosts","auditLogs","types"):
                if c in resp: items_key = c; break
            if not items_key: return [resp]
        all_items.extend(resp.get(items_key, []))
        while resp and resp.get("nextPageKey"):
            np = {"nextPageKey": resp["nextPageKey"]}
            if "pageSize" in params: np["pageSize"] = params["pageSize"]
            resp = self.get(endpoint, np)
            if resp and items_key in resp: all_items.extend(resp[items_key])
        return all_items

    # ── Collectors ──
    def get_cluster_version(self):
        r = self.get("/api/v1/config/clusterversion")
        return r.get("version", "unknown") if r else None

    def get_entities_by_type(self, etype, fields="+properties,+tags,+managementZones,+fromRelationships,+toRelationships"):
        return self.get_paginated("/api/v2/entities", {"entitySelector": f'type("{etype}")', "fields": fields, "pageSize": 500, "from": "now-72h"}, "entities")

    def get_problems(self, days=30, status=None):
        p = {"from": f"now-{days}d", "pageSize": 500, "fields": "+evidenceDetails,+impactAnalysis,+recentComments"}
        if status: p["problemSelector"] = f'status("{status}")'
        return self.get_paginated("/api/v2/problems", p, "problems")

    def get_settings(self, schema):
        return self.get_paginated("/api/v2/settings/objects", {"schemaIds": schema, "scopes": "environment", "pageSize": 500}, "items")

    def get_active_gates(self):   return self.get_paginated("/api/v2/activeGates", {"pageSize": 500}, "activeGates")
    def get_oneagents(self):      return self.get_paginated("/api/v2/oneAgents", {"pageSize": 500})
    def get_slos(self):           return self.get_paginated("/api/v2/slo", {"pageSize": 100, "timeFrame": "CURRENT", "evaluate": "true"}, "slo")
    def get_extensions(self):     return self.get_paginated("/api/v2/extensions", {"pageSize": 100}, "extensions")
    def get_synthetic(self):      return self.get_paginated("/api/v2/synthetic/monitors", {"pageSize": 500}, "monitors")
    def get_network_zones(self):
        r = self.get("/api/v2/networkZones"); return r.get("networkZones", []) if r else []
    def get_audit_logs(self, days=30):
        return self.get_paginated("/api/v2/auditlogs", {"from": f"now-{days}d", "pageSize": 500, "filter": 'category("CONFIG")'}, "auditLogs")

    def query_metric(self, key, resolution="1d", from_t="now-30d"):
        return self.get("/api/v2/metrics/query", {"metricSelector": key, "resolution": resolution, "from": from_t})

    def check_deprecated_v1(self) -> Dict[str, Any]:
        probes = {
            "/api/v1/timeseries": "Timeseries v1", "/api/v1/entity/infrastructure/hosts": "Smartscape Hosts",
            "/api/v1/entity/services": "Smartscape Services", "/api/v1/problem/feed": "Problems v1",
            "/api/v1/events": "Events v1", "/api/config/v1/autoTags": "Config v1: AutoTags",
            "/api/config/v1/alertingProfiles": "Config v1: Alerting", "/api/config/v1/notifications": "Config v1: Notifications",
            "/api/config/v1/managementZones": "Config v1: MgmtZones",
        }
        return {ep: {"name": n, "accessible": self.get(ep, {"relativeTime": "hour", "pageSize": "1"}) is not None,
                      "info": DEPRECATED_API_MAP.get(ep.split("?")[0], {})} for ep, n in probes.items()}

    def validate_token_scopes(self):
        tests = {
            "entities.read": ("/api/v2/entities", {"entitySelector": 'type("HOST")', "pageSize": 1}),
            "metrics.read": ("/api/v2/metrics", {"pageSize": 1}),
            "problems.read": ("/api/v2/problems", {"pageSize": 1}),
            "settings.read": ("/api/v2/settings/objects", {"schemaIds": "builtin:alerting.profile", "pageSize": 1}),
            "activeGates.read": ("/api/v2/activeGates", {"pageSize": 1}),
            "slo.read": ("/api/v2/slo", {"pageSize": 1}),
            "oneAgents.read": ("/api/v2/oneAgents", {"pageSize": 1}),
            "extensions.read": ("/api/v2/extensions", {"pageSize": 1}),
        }
        return {s: self.get(e, p) is not None for s, (e, p) in tests.items()}


# ═══════════════════════════════════════════════════════════════════
#  ENVIRONMENT ANALYZER
# ═══════════════════════════════════════════════════════════════════

class EnvironmentAnalyzer:
    def __init__(self, client: DynatraceClient, lookback_days=30):
        self.c = client
        self.days = lookback_days
        self.data: Dict[str, Any] = {}
        self.gaps: List[Dict] = []
        self.recs: List[Dict] = []

    def run(self) -> dict:
        n = self.c.name
        log.info(f"{'='*55}\n  Analyzing: {n}\n{'='*55}")
        self._version(); self._scopes(); self._entities(); self._problems()
        self._activegates(); self._governance(); self._alerting(); self._slos()
        self._extensions(); self._synthetic(); self._netzones(); self._oneagents()
        self._ingestion(); self._anomaly_detection(); self._deprecated()
        self._gap_analysis()
        log.info(f"[{n}] Done: {len(self.gaps)} gaps, {len(self.recs)} recs, {self.c._call_count} calls")
        return {"name": n, "url": self.c.base_url, "type": self.c.env_type,
                "timestamp": datetime.now().isoformat(), "data": self.data,
                "gaps": self.gaps, "recommendations": self.recs, "api_calls": self.c._call_count}

    def _version(self):
        log.info(f"[{self.c.name}] Cluster version...")
        self.data["version"] = self.c.get_cluster_version()

    def _scopes(self):
        log.info(f"[{self.c.name}] Validating scopes...")
        self.data["scopes"] = self.c.validate_token_scopes()
        missing = [s for s, ok in self.data["scopes"].items() if not ok]
        if missing:
            self.gaps.append({"category": "Security", "severity": "HIGH",
                              "finding": f"Token missing: {', '.join(missing)}", "impact": "Incomplete audit"})

    def _entities(self):
        log.info(f"[{self.c.name}] Entity topology...")
        self.data["entities"], ec = {}, {}
        for t in SMARTSCAPE_ENTITY_TYPES:
            ents = self.c.get_entities_by_type(t)
            self.data["entities"][t] = ents; ec[t] = len(ents)
            if ents: log.info(f"[{self.c.name}]   {t}: {len(ents)}")
        self.data["entity_counts"] = ec

    def _problems(self):
        log.info(f"[{self.c.name}] Problems ({self.days}d)...")
        probs = self.c.get_problems(self.days)
        self.data["problems_raw"] = probs
        st, sv, noise = defaultdict(int), defaultdict(int), defaultdict(int)
        for p in probs:
            st[p.get("status", "?")] += 1; sv[p.get("severityLevel", "?")] += 1
            noise[p.get("title", "?")] += 1
        oc = st.get("OPEN", 0)
        top_noise = sorted(noise.items(), key=lambda x: -x[1])[:15]
        self.data["problem_stats"] = {
            "total": len(probs), "by_status": dict(st), "by_severity": dict(sv),
            "open_count": oc, "top_noise_sources": top_noise,
            "top_open": [{"title": p.get("title","?"), "severity": p.get("severityLevel","?"),
                          "status": p.get("status","?")} for p in probs if p.get("status") == "OPEN"][:20]}
        self.data["davis_ai_summary"] = (
            f"{len(probs)} problems ({self.days}d). {oc} open. "
            f"Top noise: '{top_noise[0][0][:50]}' ({top_noise[0][1]}x)" if top_noise
            else f"No problems in {self.days}d.")
        if oc > 20:
            self.gaps.append({"category": "Problem Mgmt", "severity": "HIGH",
                              "finding": f"{oc} open problems", "impact": "Alert fatigue in GxP env"})
            self.recs.append({"category": "Problem Mgmt", "priority": "P1",
                              "action": "Tune anomaly detection, review alerting profiles, suppress noise", "effort": "Medium"})
        if top_noise and top_noise[0][1] >= 10:
            self.gaps.append({"category": "Noise", "severity": "MEDIUM",
                              "finding": f"'{top_noise[0][0][:45]}' recurred {top_noise[0][1]}x", "impact": "Alert fatigue"})
            self.recs.append({"category": "Noise", "priority": "P1",
                              "action": f"Tune/suppress: '{top_noise[0][0][:45]}'", "effort": "Low"})

    def _activegates(self):
        log.info(f"[{self.c.name}] ActiveGates...")
        ags = self.c.get_active_gates(); self.data["activegates"] = ags
        if not ags:
            self.gaps.append({"category": "Infra", "severity": "MEDIUM",
                              "finding": "No ActiveGates", "impact": "Cannot verify AG health"}); return
        bad = [a.get("hostname","?") for a in ags if a.get("autoUpdateStatus") == "OUTDATED"]
        if bad:
            self.gaps.append({"category": "Infra", "severity": "HIGH",
                              "finding": f"{len(bad)} AG(s) outdated", "impact": "Security risk"})
            self.recs.append({"category": "Infra", "priority": "P1",
                              "action": f"Update: {', '.join(bad[:5])}", "effort": "Low"})

    def _governance(self):
        log.info(f"[{self.c.name}] Governance config...")
        self.data["mgmt_zones"] = self.c.get_settings("builtin:management-zones")
        self.data["auto_tags"] = self.c.get_settings("builtin:tags.auto-tagging")

    def _alerting(self):
        log.info(f"[{self.c.name}] Alerting config...")
        self.data["alerting_profiles"] = self.c.get_settings("builtin:alerting.profile")
        self.data["notifications"] = self.c.get_settings("builtin:problem.notifications")
        self.data["maintenance_windows"] = self.c.get_settings("builtin:alerting.maintenance-window")
        # Build alert list
        self.data["all_alerts_configured"] = [
            f"profile: {i.get('value',{}).get('name', i.get('value',{}).get('displayName','?'))}"
            for i in self.data["alerting_profiles"]]
        if not self.data["alerting_profiles"]:
            self.gaps.append({"category": "Alerting", "severity": "HIGH",
                              "finding": "No alerting profiles", "impact": "Noise from defaults"})
        if not self.data["notifications"]:
            self.gaps.append({"category": "Alerting", "severity": "CRITICAL",
                              "finding": "No notification rules", "impact": "Silent failures"})
            self.recs.append({"category": "Alerting", "priority": "P0",
                              "action": "Configure PagerDuty/ServiceNow/email notifications", "effort": "Medium"})

    def _slos(self):
        log.info(f"[{self.c.name}] SLOs...")
        slos = self.c.get_slos(); self.data["slos"] = slos
        if not slos:
            self.gaps.append({"category": "SLO/SRE", "severity": "MEDIUM",
                              "finding": "No SLOs defined", "impact": "No reliability targets"})
            self.recs.append({"category": "SLO/SRE", "priority": "P2",
                              "action": "Define SLOs for critical services", "effort": "Medium"})
        else:
            breached = [s for s in slos if isinstance(s.get("evaluatedPercentage"), (int,float))
                        and isinstance(s.get("target"), (int,float)) and s["evaluatedPercentage"] < s["target"]]
            if breached:
                self.gaps.append({"category": "SLO/SRE", "severity": "HIGH",
                                  "finding": f"{len(breached)} SLO(s) breaching", "impact": "Targets not met"})

    def _extensions(self):
        log.info(f"[{self.c.name}] Extensions 2.0...")
        self.data["extensions"] = self.c.get_extensions()

    def _synthetic(self):
        log.info(f"[{self.c.name}] Synthetic...")
        self.data["synthetic"] = self.c.get_synthetic()

    def _netzones(self):
        log.info(f"[{self.c.name}] Network Zones...")
        self.data["network_zones"] = self.c.get_network_zones()

    def _oneagents(self):
        log.info(f"[{self.c.name}] OneAgents...")
        agents = self.c.get_oneagents(); self.data["oneagents"] = agents
        if isinstance(agents, list) and agents:
            bad = [a.get("hostInfo",{}).get("displayName","?") for a in agents
                   if isinstance(a, dict) and a.get("updateStatus") in ("OUTDATED","SUPPRESSED")]
            if bad:
                self.gaps.append({"category": "Agents", "severity": "HIGH",
                                  "finding": f"{len(bad)} OA outdated/suppressed", "impact": "Missing patches"})
                self.recs.append({"category": "Agents", "priority": "P1",
                                  "action": "Enable auto-update per GxP change control", "effort": "Medium"})

    def _ingestion(self):
        log.info(f"[{self.c.name}] Ingestion metrics...")
        ing = {}
        for name, key in INGESTION_METRICS.items():
            try:
                r = self.c.query_metric(key, "1d", f"now-{self.days}d")
                total = 0.0
                if r and "result" in r:
                    for s in r["result"]:
                        for d in s.get("data", []):
                            total += sum(v for v in d.get("values", []) if v is not None)
                ing[name] = round(total, 2)
            except: ing[name] = 0
        self.data["ingestion"] = ing

    def _anomaly_detection(self):
        log.info(f"[{self.c.name}] Anomaly detection...")
        ad = {}
        for schema in ANOMALY_SCHEMAS:
            objs = self.c.get_settings(schema)
            short = schema.split(".")[-1]
            ad[short] = len(objs)
            self.data["all_alerts_configured"].extend(
                [f"anomaly.{short}: {o.get('value',{}).get('name', o.get('value',{}).get('displayName','?'))}"
                 for o in objs][:25])
        self.data["anomaly_detection"] = ad

    def _deprecated(self):
        log.info(f"[{self.c.name}] Probing deprecated APIs...")
        dep = self.c.check_deprecated_v1(); self.data["deprecated_apis"] = dep
        for ep, info in dep.items():
            if info["accessible"]:
                ai = info.get("info", {})
                self.gaps.append({"category": "API Deprecation", "severity": ai.get("severity","MEDIUM"),
                                  "finding": f"Deprecated: {ep}", "impact": f"EOL:{ai.get('eol','TBD')} → {ai.get('replacement','v2')}"})
        self.recs.append({"category": "API Deprecation", "priority": "P1",
                          "action": "Audit scripts for v1 usage. Migrate to v2/Settings 2.0.", "effort": "High"})

    def _gap_analysis(self):
        ec = self.data.get("entity_counts", {})
        if ec.get("HOST", 0) == 0:
            self.gaps.append({"category": "Coverage", "severity": "CRITICAL",
                              "finding": "No hosts", "impact": "Zero infra visibility"})
        if ec.get("SERVICE", 0) > 0 and ec.get("APPLICATION", 0) == 0:
            self.gaps.append({"category": "Coverage", "severity": "MEDIUM",
                              "finding": "No RUM Applications", "impact": "No UX visibility"})
            self.recs.append({"category": "Coverage", "priority": "P2", "action": "Enable RUM", "effort": "Low"})
        if ec.get("HTTP_CHECK", 0) == 0 and ec.get("BROWSER_MONITOR", 0) == 0:
            self.gaps.append({"category": "Coverage", "severity": "MEDIUM",
                              "finding": "No synthetic monitors", "impact": "No proactive checks"})
            self.recs.append({"category": "Coverage", "priority": "P2",
                              "action": "Create HTTP checks for critical endpoints", "effort": "Medium"})
        if not self.data.get("mgmt_zones"):
            self.gaps.append({"category": "Governance", "severity": "MEDIUM",
                              "finding": "No management zones", "impact": "No RBAC segmentation (GxP)"})
            self.recs.append({"category": "Governance", "priority": "P1",
                              "action": "Define MZs for app tiers/GxP boundaries", "effort": "Medium"})
        if len(self.data.get("auto_tags", [])) < 3:
            self.recs.append({"category": "Governance", "priority": "P2",
                              "action": "Auto-tagging: env, tier, owner, cost-center, GxP-class", "effort": "Medium"})
        if not self.data.get("network_zones"):
            self.recs.append({"category": "Network", "priority": "P3",
                              "action": "Consider network zones for DMZ routing", "effort": "Low"})


# ═══════════════════════════════════════════════════════════════════
#  SMARTSCAPE DIAGRAM
# ═══════════════════════════════════════════════════════════════════

class SmartscapeDiagram:
    LAYERS = {
        "APPLICATION": {"color": "#6F2DA8", "shape": "doubleoctagon", "label": "Applications"},
        "SERVICE": {"color": "#1496FF", "shape": "component", "label": "Services"},
        "PROCESS_GROUP": {"color": "#2AB06F", "shape": "box3d", "label": "Process Groups"},
        "HOST": {"color": "#FF6A00", "shape": "box", "label": "Hosts"},
        "KUBERNETES_CLUSTER": {"color": "#326CE5", "shape": "tab", "label": "K8s Clusters"},
    }

    def __init__(self, env, entities, outdir):
        self.env, self.entities, self.outdir = env, entities, outdir

    def generate(self) -> Optional[str]:
        dot = graphviz.Digraph(name=f"smartscape_{self.env}", format="png", engine="dot")
        dot.attr(rankdir="TB", bgcolor="#1A1A2E", fontcolor="white", fontname="Helvetica",
                 label=f"Smartscape — {self.env}", labelloc="t", fontsize="20", dpi="150",
                 pad="0.5", nodesep="0.4", ranksep="0.8")
        dot.attr("node", fontname="Helvetica", fontsize="9", fontcolor="white", style="filled")
        dot.attr("edge", color="#555555", arrowsize="0.6", penwidth="0.8")
        id_map = {}
        for etype, cfg in self.LAYERS.items():
            items = self.entities.get(etype, [])
            if not items: continue
            show, overflow = items[:30], max(0, len(items)-30)
            with dot.subgraph(name=f"cluster_{etype}") as s:
                s.attr(label=f"{cfg['label']} ({len(items)})", style="dashed",
                       color=cfg["color"], fontcolor=cfg["color"], fontsize="12")
                for e in show:
                    eid = e.get("entityId",""); nid = eid.replace("-","_").replace(".","_")
                    id_map[eid] = nid
                    lbl = e.get("displayName", eid)[:30]
                    s.node(nid, label=lbl, shape=cfg["shape"], fillcolor=cfg["color"], color=cfg["color"])
                if overflow:
                    s.node(f"ov_{etype}", label=f"+{overflow} more", shape="plaintext",
                           fontcolor=cfg["color"], fillcolor="#1A1A2E")
        edges = 0
        for items in self.entities.values():
            for e in items:
                src = id_map.get(e.get("entityId",""))
                if not src: continue
                for rt in ("calls","runsOn","isProcessOf","runs","contains"):
                    for r in e.get("fromRelationships",{}).get(rt,[]):
                        tid = r.get("id","") if isinstance(r, dict) else r
                        tgt = id_map.get(tid)
                        if tgt and edges < 200: dot.edge(src, tgt, color="#555555AA"); edges += 1
        try:
            p = os.path.join(self.outdir, f"smartscape_{self.env}")
            dot.render(p, cleanup=True); return f"{p}.png"
        except Exception as e:
            log.error(f"Diagram failed: {e}"); return None


# ═══════════════════════════════════════════════════════════════════
#  HTML DASHBOARD (merged from main_pdf.py)
# ═══════════════════════════════════════════════════════════════════

class HTMLDashboard:
    def __init__(self, results, outdir, diagrams):
        self.results, self.outdir, self.diagrams = results, outdir, diagrams

    def generate(self) -> str:
        envs = [r["name"] for r in self.results]
        snap = json.dumps([{"Env": r["name"], "Hosts": r["data"].get("entity_counts",{}).get("HOST",0),
                            "Services": r["data"].get("entity_counts",{}).get("SERVICE",0),
                            "Apps": r["data"].get("entity_counts",{}).get("APPLICATION",0),
                            "AGs": len(r["data"].get("activegates",[])),
                            "PGs": r["data"].get("entity_counts",{}).get("PROCESS_GROUP",0)} for r in self.results])
        probs = json.dumps([{"env": r["name"], "open": r["data"].get("problem_stats",{}).get("open_count",0)} for r in self.results])
        noise = "[]"
        for r in self.results:
            ns = r["data"].get("problem_stats",{}).get("top_noise_sources",[])
            if ns: noise = json.dumps([{"t": t[:50], "c": c} for t,c in ns[:10]]); break
        ing = json.dumps([{"env": r["name"], **r["data"].get("ingestion",{})} for r in self.results])
        gaps = json.dumps([{"env": r["name"], **g} for r in self.results for g in r["gaps"]])
        recs = json.dumps([{"env": r["name"], **rc} for r in self.results for rc in r["recommendations"]])
        davis = "".join(f'<div class="alert alert-info mb-2"><b>{r["name"]}:</b> {r["data"].get("davis_ai_summary","N/A")}</div>' for r in self.results)
        alerts = "".join(f'<li class="list-group-item py-1 small">[{r["name"]}] {a}</li>' for r in self.results for a in r["data"].get("all_alerts_configured",[])[:20])
        imgs = "".join(f'<div class="col-md-4 mb-3"><h6>{n}</h6><img src="{os.path.basename(p)}" class="img-fluid shadow rounded"></div>' for n,p in self.diagrams.items() if p and os.path.exists(p))
        gap_matrix = json.dumps([{"Env":r["name"], "MZ":len(r["data"].get("mgmt_zones",[])),
                                   "Open":r["data"].get("problem_stats",{}).get("open_count",0),
                                   "SLOs":len(r["data"].get("slos",[])), "Synth":len(r["data"].get("synthetic",[])),
                                   "Tags":len(r["data"].get("auto_tags",[])), "Gaps":len(r["gaps"])} for r in self.results])

        html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DT Audit v4.0</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<style>body{{background:#f0f2f5;font-family:'Segoe UI',sans-serif}}.nav-tabs .nav-link{{color:#6F2DA8}}.nav-tabs .nav-link.active{{background:#6F2DA8;color:#fff;border-color:#6F2DA8}}.severity-CRITICAL{{color:#DC172A;font-weight:700}}.severity-HIGH{{color:#FF6A00;font-weight:700}}.severity-MEDIUM{{color:#1496FF}}.table th{{background:#6F2DA8;color:#fff;font-size:.8rem}}.table td{{font-size:.8rem}}</style></head>
<body class="p-4"><div class="container-fluid">
<h2 class="text-center mb-1" style="color:#6F2DA8">Dynatrace Audit v4.0</h2>
<p class="text-center text-muted mb-3">{datetime.now().strftime('%B %d, %Y %H:%M')}</p>
<ul class="nav nav-tabs mb-3" id="t" role="tablist">
<li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#ov">Overview</a></li>
<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#dv">Davis AI</a></li>
<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#ns">Noise</a></li>
<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#al">Alerts</a></li>
<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#ig">Ingestion</a></li>
<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#gp">Gaps</a></li>
<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#rc">Recs</a></li>
<li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#ss">Smartscape</a></li></ul>
<div class="tab-content">
<div class="tab-pane fade show active" id="ov"><div class="row"><div class="col-md-6"><div id="cp"></div></div><div class="col-md-6"><div id="ce"></div></div></div><div id="ts" class="mt-3"></div></div>
<div class="tab-pane fade" id="dv"><h5>Davis AI</h5>{davis}</div>
<div class="tab-pane fade" id="ns"><div class="row"><div class="col-md-8"><div id="cn"></div></div><div class="col-md-4"><div class="card p-3 mt-4"><h6>Action</h6><p class="small">Tune anomaly rules or suppress recurring noise.</p></div></div></div></div>
<div class="tab-pane fade" id="al"><h5>Configured Alerts</h5><ul class="list-group">{alerts or '<li class="list-group-item">None</li>'}</ul></div>
<div class="tab-pane fade" id="ig"><div id="ci"></div></div>
<div class="tab-pane fade" id="gp"><h5>Gap Matrix</h5><div id="tgm"></div><h5 class="mt-3">All Gaps</h5><div id="tg"></div></div>
<div class="tab-pane fade" id="rc"><h5>Recommendations</h5><div id="tr"></div></div>
<div class="tab-pane fade" id="ss"><div class="row">{imgs or '<p class="col-12 text-muted">No diagrams.</p>'}</div></div>
</div></div>
<script>
const P={probs},S={snap},N={noise},I={ing},G={gaps},R={recs},GM={gap_matrix};
Plotly.newPlot('cp',[{{values:P.map(d=>d.open),labels:P.map(d=>d.env),type:'pie',marker:{{colors:['#6F2DA8','#1496FF','#2AB06F','#FF6A00']}}}}],{{title:'Open Problems',height:320}});
Plotly.newPlot('ce',[{{x:S.map(d=>d.Env),y:S.map(d=>d.Hosts),name:'Hosts',type:'bar'}},{{x:S.map(d=>d.Env),y:S.map(d=>d.Services),name:'Svc',type:'bar'}},{{x:S.map(d=>d.Env),y:S.map(d=>d.Apps),name:'App',type:'bar'}}],{{title:'Entities',barmode:'group',height:320}});
if(N.length)Plotly.newPlot('cn',[{{x:N.map(d=>d.t),y:N.map(d=>d.c),type:'bar',marker:{{color:'#FF6A00'}}}}],{{title:'Top Noise',height:350,xaxis:{{tickangle:-25}}}});
if(I.length){{const ks=Object.keys(I[0]).filter(k=>k!=='env');Plotly.newPlot('ci',ks.map(k=>({{x:I.map(d=>d.env),y:I.map(d=>d[k]||0),name:k,type:'bar'}})),{{title:'Ingestion (30d)',barmode:'group',height:350}})}}
function rt(id,d){{if(!d.length){{document.getElementById(id).innerHTML='<p>No data</p>';return}}let h='<table class="table table-sm table-bordered"><thead><tr>';Object.keys(d[0]).forEach(k=>h+='<th>'+k+'</th>');h+='</tr></thead><tbody>';d.forEach(r=>{{h+='<tr>';Object.entries(r).forEach(([k,v])=>{{let c=k==='severity'?'severity-'+v:'';h+='<td class="'+c+'">'+v+'</td>'}});h+='</tr>'}});h+='</tbody></table>';document.getElementById(id).innerHTML=h}}
rt('ts',S);rt('tgm',GM);rt('tg',G);rt('tr',R);
</script></body></html>"""
        out = os.path.join(self.outdir, "dashboard_v4.0.html")
        with open(out, "w", encoding="utf-8") as f: f.write(html)
        log.info(f"HTML: {out}"); return out


# ═══════════════════════════════════════════════════════════════════
#  PDF REPORT
# ═══════════════════════════════════════════════════════════════════

class PDFReport:
    def __init__(self, results, path, diagrams):
        self.results, self.path, self.diagrams = results, path, diagrams
        self.styles = getSampleStyleSheet()
        for name, kw in [
            ("CoverTitle", {"fontSize": 28, "textColor": colors.HexColor(DT_PURPLE), "spaceAfter": 20, "alignment": TA_CENTER}),
            ("CoverSub", {"fontSize": 14, "textColor": colors.HexColor("#666"), "alignment": TA_CENTER, "spaceAfter": 10}),
            ("SH", {"parent": self.styles["Heading1"], "fontSize": 16, "textColor": colors.HexColor(DT_PURPLE), "spaceBefore": 16, "spaceAfter": 8}),
            ("SS", {"parent": self.styles["Heading2"], "fontSize": 13, "textColor": colors.HexColor(DT_BLUE), "spaceBefore": 10, "spaceAfter": 6}),
            ("BT", {"fontSize": 9, "leading": 12, "spaceAfter": 4}),
            ("SN", {"fontSize": 7, "textColor": colors.HexColor("#999")}),
            ("CT", {"fontSize": 8, "leading": 10}),
        ]:
            parent = kw.pop("parent", self.styles["Normal"])
            self.styles.add(ParagraphStyle(name, parent=parent, **kw))

    def _tbl(self, data, cw=None, hc=None):
        hc = hc or colors.HexColor(DT_PURPLE)
        rows = []
        for i, row in enumerate(data):
            st = ParagraphStyle("_hc", parent=self.styles["CT"], textColor=colors.white, fontName="Helvetica-Bold") if i == 0 else self.styles["CT"]
            rows.append([Paragraph(str(c), st) for c in row])
        t = Table(rows, colWidths=cw, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),hc), ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),8),
            ("ALIGN",(0,0),(-1,-1),"LEFT"), ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#CCC")),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#F5F5FF")]),
            ("TOPPADDING",(0,0),(-1,-1),4), ("BOTTOMPADDING",(0,0),(-1,-1),4),
            ("LEFTPADDING",(0,0),(-1,-1),4), ("RIGHTPADDING",(0,0),(-1,-1),4)]))
        return t

    def generate(self):
        doc = SimpleDocTemplate(self.path, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm, leftMargin=15*mm, rightMargin=15*mm)
        s = []
        # Cover
        s += [Spacer(1,80), Paragraph("Dynatrace Environment", self.styles["CoverTitle"]),
              Paragraph("Analysis Report v4.0", self.styles["CoverTitle"]), Spacer(1,20),
              HRFlowable(width="60%", color=colors.HexColor(DT_PURPLE), thickness=2), Spacer(1,20),
              Paragraph(f"Environments: {' | '.join(r['name'] for r in self.results)}", self.styles["CoverSub"]),
              Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y %H:%M')}", self.styles["CoverSub"]),
              Paragraph("Observability Operations", self.styles["CoverSub"]), PageBreak()]

        # Exec Summary
        s.append(Paragraph("1. Executive Summary", self.styles["SH"]))
        tg = sum(len(r["gaps"]) for r in self.results)
        tr = sum(len(r["recommendations"]) for r in self.results)
        cr = sum(1 for r in self.results for g in r["gaps"] if g["severity"]=="CRITICAL")
        rows = [["Metric","Value"],["Environments",str(len(self.results))],["Gaps",str(tg)],
                ["Critical",str(cr)],["Recommendations",str(tr)]]
        for r in self.results:
            ec = r["data"].get("entity_counts",{})
            rows += [[f"{r['name']} Entities",str(sum(ec.values()))],
                     [f"{r['name']} Open Problems",str(r["data"].get("problem_stats",{}).get("open_count",0))]]
        s += [self._tbl(rows, [250,200]), PageBreak()]

        # Entities
        s.append(Paragraph("2. Entities", self.styles["SH"]))
        for r in self.results:
            s.append(Paragraph(f"{r['name']} ({r['type']}) — v{r['data'].get('version','?')}", self.styles["SS"]))
            ec = r["data"].get("entity_counts",{})
            if ec:
                s.append(self._tbl([["Type","Count"]]+[[t,str(c)] for t,c in sorted(ec.items(), key=lambda x:-x[1]) if c>0], [280,100]))
            s.append(Spacer(1,6))
        s.append(PageBreak())

        # Smartscape
        s.append(Paragraph("3. Smartscape", self.styles["SH"]))
        for n, p in self.diagrams.items():
            if p and os.path.exists(p):
                s.append(Paragraph(n, self.styles["SS"]))
                try:
                    img = Image(p); w,h = img.imageWidth, img.imageHeight
                    if w>0 and h>0: ratio=min(500/w,580/h); img.drawWidth,img.drawHeight=w*ratio,h*ratio
                    s.append(img)
                except: pass
        s.append(PageBreak())

        # Deprecated
        s.append(Paragraph("4. Deprecated API Audit", self.styles["SH"]))
        for r in self.results:
            s.append(Paragraph(r["name"], self.styles["SS"]))
            dep = r["data"].get("deprecated_apis",{})
            if dep:
                s.append(self._tbl([["Endpoint","Status","Replacement","EOL"]]+
                    [[ep,"LIVE" if i["accessible"] else "OK",i.get("info",{}).get("replacement","-")[:48],
                      i.get("info",{}).get("eol","TBD")] for ep,i in dep.items()], [135,45,200,55]))
        s += [Spacer(1,8), Paragraph("Full Reference", self.styles["SS"]),
              self._tbl([["Endpoint","Replacement","Since","EOL","Sev"]]+
                  [[e,i["replacement"][:40],i["deprecated_since"][:20],i["eol"],i["severity"]]
                   for e,i in DEPRECATED_API_MAP.items()], [110,135,80,55,50],
                  hc=colors.HexColor("#8B0000")), PageBreak()]

        # Problems + Noise + Davis
        s.append(Paragraph("5. Problems, Noise & Davis AI", self.styles["SH"]))
        for r in self.results:
            s.append(Paragraph(r["name"], self.styles["SS"]))
            ps = r["data"].get("problem_stats",{})
            if ps:
                s.append(self._tbl([["Metric","Value"],["Total",str(ps.get("total",0))],["Open",str(ps.get("open_count",0))]]+
                    [[f"  {k}",str(v)] for k,v in ps.get("by_severity",{}).items()], [280,100]))
                ns = ps.get("top_noise_sources",[])
                if ns:
                    s += [Paragraph("Noise Sources", self.styles["SS"]),
                          self._tbl([["Problem","Count"]]+[[t[:55],str(c)] for t,c in ns[:10]], [340,60])]
            s += [Paragraph(f"Davis: {r['data'].get('davis_ai_summary','N/A')}", self.styles["BT"]), Spacer(1,6)]
        s.append(PageBreak())

        # Alerting + Anomaly
        s.append(Paragraph("6. Alerting & Anomaly Detection", self.styles["SH"]))
        for r in self.results:
            s.append(Paragraph(r["name"], self.styles["SS"]))
            rows = [["Config","Count"],
                    ["Alerting Profiles",str(len(r["data"].get("alerting_profiles",[])))],
                    ["Notifications",str(len(r["data"].get("notifications",[])))],
                    ["Maintenance Windows",str(len(r["data"].get("maintenance_windows",[])))]]
            for k,v in r["data"].get("anomaly_detection",{}).items(): rows.append([f"Anomaly: {k}",str(v)])
            s.append(self._tbl(rows, [280,100]))
        s.append(PageBreak())

        # SLOs
        s.append(Paragraph("7. SLOs", self.styles["SH"]))
        for r in self.results:
            s.append(Paragraph(r["name"], self.styles["SS"]))
            slos = r["data"].get("slos",[])
            if slos:
                s.append(self._tbl([["SLO","Target","Actual","Status"]]+
                    [[str(sl.get("name","?"))[:38],str(sl.get("target","-")),
                      f"{sl['evaluatedPercentage']:.1f}" if isinstance(sl.get("evaluatedPercentage"),(int,float)) else "-",
                      "OK" if isinstance(sl.get("evaluatedPercentage"),(int,float)) and isinstance(sl.get("target"),(int,float)) and sl["evaluatedPercentage"]>=sl["target"] else "BREACH"]
                     for sl in slos[:20]], [175,65,65,55]))
            else: s.append(Paragraph("No SLOs.", self.styles["BT"]))
        s.append(PageBreak())

        # Ingestion
        s.append(Paragraph("8. Data Ingestion (30d)", self.styles["SH"]))
        for r in self.results:
            s.append(Paragraph(r["name"], self.styles["SS"]))
            ing = r["data"].get("ingestion",{})
            if ing: s.append(self._tbl([["Metric","Value"]]+[[k,f"{v:,.2f}"] for k,v in ing.items()], [280,100]))
        s.append(PageBreak())

        # Infra
        s.append(Paragraph("9. Infrastructure", self.styles["SH"]))
        for r in self.results:
            ags = r["data"].get("activegates",[])
            if ags:
                s += [Paragraph(f"{r['name']} AGs", self.styles["SS"]),
                      self._tbl([["Host","Version","OS","Modules"]]+
                          [[str(a.get("hostname","-"))[:28],str(a.get("version","-"))[:18],str(a.get("osType","-")),
                            ", ".join(m.get("type","") for m in a.get("modules",[]))[:45] or "-"] for a in ags[:12]],
                          [115,75,55,190])]
        s.append(PageBreak())

        # Governance
        s.append(Paragraph("10. Governance", self.styles["SH"]))
        for r in self.results:
            s += [Paragraph(r["name"], self.styles["SS"]),
                  self._tbl([["Item","Count"],["Mgmt Zones",str(len(r["data"].get("mgmt_zones",[])))],
                             ["Auto-Tags",str(len(r["data"].get("auto_tags",[])))],
                             ["Network Zones",str(len(r["data"].get("network_zones",[])))],
                             ["Synthetic",str(len(r["data"].get("synthetic",[])))],
                             ["Extensions",str(len(r["data"].get("extensions",[])))]], [280,100])]
        s.append(PageBreak())

        # Gaps
        s.append(Paragraph("11. All Gaps", self.styles["SH"]))
        ag = [[r["name"],g["severity"],g["category"],g["finding"],g["impact"]] for r in self.results for g in r["gaps"]]
        if ag:
            ag.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x[1],4))
            s.append(self._tbl([["Env","Sev","Cat","Finding","Impact"]]+ag, [48,48,62,160,130], hc=colors.HexColor("#8B0000")))
        s.append(PageBreak())

        # Recs
        s.append(Paragraph("12. Recommendations", self.styles["SH"]))
        seen, ar = set(), []
        for r in self.results:
            for rc in r["recommendations"]:
                k = rc["action"][:80]
                if k not in seen: seen.add(k); ar.append([r["name"],rc["priority"],rc["category"],rc["action"],rc["effort"]])
        if ar:
            ar.sort(key=lambda x: {"P0":0,"P1":1,"P2":2,"P3":3}.get(x[1],4))
            s.append(self._tbl([["Env","Pri","Cat","Action","Effort"]]+ar, [48,32,62,215,42]))
        s.append(PageBreak())

        # Appendix
        s.append(Paragraph("13. Token Scopes", self.styles["SH"]))
        for r in self.results:
            sc = r["data"].get("scopes",{})
            if sc:
                s += [Paragraph(r["name"], self.styles["SS"]),
                      self._tbl([["Scope","Status"]]+[[k,"OK" if v else "MISSING"] for k,v in sorted(sc.items())], [250,150])]
        s += [Spacer(1,20), HRFlowable(width="100%",color=colors.HexColor("#CCC"),thickness=0.5),
              Paragraph("Dynatrace Analyzer v4.0 — Observability Operations", self.styles["SN"])]

        doc.build(s)
        log.info(f"PDF: {self.path}")


# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description="Dynatrace Multi-Environment Analyzer v4.0")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--output", default=None)
    ap.add_argument("--html", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--generate-template", action="store_true")
    ap.add_argument("--skip-diagrams", action="store_true")
    ap.add_argument("--lookback", type=int)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.verbose: logging.getLogger().setLevel(logging.DEBUG)
    if args.generate_template:
        Path("config.yaml.template").write_text(DEFAULT_CONFIG_TEMPLATE)
        log.info("Template: config.yaml.template"); return

    cfg = load_config(args.config)
    st = cfg.get("settings", {})
    outdir = st.get("output_dir", "./dt_reports"); os.makedirs(outdir, exist_ok=True)
    lookback = args.lookback or st.get("lookback_days", 30)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = args.output or os.path.join(outdir, f"dt_analysis_{ts}.pdf")
    do_html = args.html or st.get("generate_html", True)
    do_json = args.json or st.get("generate_json", True)

    results, diagrams = [], {}
    for ec in cfg["environments"]:
        client = DynatraceClient(ec["name"], ec["url"], ec["token"], ec.get("type","SaaS"),
                                  ec.get("verify_ssl",True), st.get("timeout_seconds",30),
                                  st.get("max_retries",3), st.get("rate_limit_pause",0.25))
        try:
            result = EnvironmentAnalyzer(client, lookback).run()
            results.append(result)
        except Exception as e:
            log.error(f"{ec['name']} failed: {e}"); traceback.print_exc()
            result = {"name":ec["name"],"url":ec["url"],"type":ec.get("type","SaaS"),
                      "timestamp":datetime.now().isoformat(),
                      "data":{"entities":{},"entity_counts":{}},
                      "gaps":[{"category":"Analysis","severity":"CRITICAL","finding":str(e),"impact":"No data"}],
                      "recommendations":[],"api_calls":0}
            results.append(result)

        if not args.skip_diagrams:
            ents = result.get("data",{}).get("entities",{})
            if any(len(v)>0 for v in ents.values()):
                diagrams[ec["name"]] = SmartscapeDiagram(ec["name"], ents, outdir).generate()
            else: diagrams[ec["name"]] = None

    # Outputs
    PDFReport(results, pdf_path, diagrams).generate()
    html_path = HTMLDashboard(results, outdir, diagrams).generate() if do_html else None
    json_path = None
    if do_json:
        json_path = os.path.join(outdir, f"dt_audit_{ts}.json")
        export = []
        for r in results:
            safe = {k:v for k,v in r.items() if k != "data"}
            safe["data"] = {k:v for k,v in r.get("data",{}).items() if k not in ("entities","problems_raw")}
            safe["data"]["entity_counts"] = r["data"].get("entity_counts",{})
            export.append(safe)
        with open(json_path, "w") as f: json.dump(export, f, indent=2, default=str)
        log.info(f"JSON: {json_path}")

    print(f"\n{'='*55}\n  ANALYSIS COMPLETE v4.0\n{'='*55}")
    for r in results:
        ec = r["data"].get("entity_counts",{})
        print(f"\n  {r['name']}: {sum(ec.values())} entities, {len(r['gaps'])} gaps, {len(r['recommendations'])} recs, {r['api_calls']} calls")
    print(f"\n  PDF:  {pdf_path}")
    if html_path: print(f"  HTML: {html_path}")
    if json_path: print(f"  JSON: {json_path}")
    for n,p in diagrams.items():
        if p: print(f"  Diagram ({n}): {p}")
    print(f"{'='*55}")

if __name__ == "__main__":
    main()
