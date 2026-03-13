#!/usr/bin/env python3
"""
Dynatrace Multi-Environment Comprehensive Analyzer
====================================================
Author  : Abhi (Observability Operations)
Purpose : Audit 3 Dynatrace environments via API v2, detect deprecated API usage,
          generate Smartscape-like architecture diagrams, identify gaps,
          and produce a consolidated PDF report with recommendations.

Required Token Scopes (per environment):
  - entities.read
  - metrics.read
  - problems.read
  - settings.read
  - events.read
  - activeGates.read
  - securityProblems.read
  - syntheticLocations.read
  - syntheticExecution.read
  - attacks.read (optional)
  - slo.read
  - extensions.read
  - networkZones.read
  - oneAgents.read
  - auditLogs.read

Usage:
  1. Copy config.yaml.template -> config.yaml
  2. Fill in your environment URLs and API tokens
  3. python dt_env_analyzer.py [--config config.yaml] [--output report.pdf]
"""

import argparse
import json
import logging
import os
import sys
import time
import traceback
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
import requests
import graphviz

# ── PDF generation ──────────────────────────────────────────────────
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ─── Logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("dt-analyzer")

# ═══════════════════════════════════════════════════════════════════
#  CONSTANTS & REFERENCE DATA
# ═══════════════════════════════════════════════════════════════════

# Full deprecated API map: deprecated endpoint → (replacement, deprecated since, EOL)
DEPRECATED_API_MAP = {
    # V1 → V2 migrations
    "/api/v1/timeseries": {
        "replacement": "/api/v2/metrics/query",
        "deprecated_since": "SaaS 1.305 / Managed 1.316",
        "eol": "End of 2025",
        "severity": "CRITICAL",
    },
    "/api/v1/entity": {
        "replacement": "/api/v2/entities",
        "deprecated_since": "1.263",
        "eol": "TBD",
        "severity": "HIGH",
    },
    "/api/v1/entity/infrastructure/hosts": {
        "replacement": "/api/v2/entities?entitySelector=type(HOST)",
        "deprecated_since": "1.263",
        "eol": "TBD",
        "severity": "HIGH",
    },
    "/api/v1/entity/infrastructure/processes": {
        "replacement": "/api/v2/entities?entitySelector=type(PROCESS_GROUP_INSTANCE)",
        "deprecated_since": "1.263",
        "eol": "TBD",
        "severity": "HIGH",
    },
    "/api/v1/entity/infrastructure/process-groups": {
        "replacement": "/api/v2/entities?entitySelector=type(PROCESS_GROUP)",
        "deprecated_since": "1.263",
        "eol": "TBD",
        "severity": "HIGH",
    },
    "/api/v1/entity/services": {
        "replacement": "/api/v2/entities?entitySelector=type(SERVICE)",
        "deprecated_since": "1.263",
        "eol": "TBD",
        "severity": "HIGH",
    },
    "/api/v1/entity/applications": {
        "replacement": "/api/v2/entities?entitySelector=type(APPLICATION)",
        "deprecated_since": "1.263",
        "eol": "TBD",
        "severity": "HIGH",
    },
    "/api/v1/problem": {
        "replacement": "/api/v2/problems",
        "deprecated_since": "SaaS 1.243 / Managed 1.244",
        "eol": "TBD",
        "severity": "HIGH",
    },
    "/api/v1/events": {
        "replacement": "/api/v2/events",
        "deprecated_since": "SaaS 1.243 / Managed 1.244",
        "eol": "TBD",
        "severity": "HIGH",
    },
    "/api/v1/tokens": {
        "replacement": "/api/v2/apiTokens",
        "deprecated_since": "1.252",
        "eol": "TBD",
        "severity": "MEDIUM",
    },
    "/api/v1/maintenance-window": {
        "replacement": "/api/v2/settings (schema: builtin:alerting.maintenance-window)",
        "deprecated_since": "SaaS 1.173 / Managed 1.174",
        "eol": "TBD",
        "severity": "MEDIUM",
    },
    "/api/config/v1/maintenanceWindows": {
        "replacement": "/api/v2/settings (schema: builtin:alerting.maintenance-window)",
        "deprecated_since": "SaaS 1.173 / Managed 1.174",
        "eol": "TBD",
        "severity": "MEDIUM",
    },
    "/api/config/v1/credentials": {
        "replacement": "/api/v2/credentials",
        "deprecated_since": "1.252",
        "eol": "TBD",
        "severity": "MEDIUM",
    },
    # Log Monitoring v2 search/export → Grail
    "/api/v2/logs/search": {
        "replacement": "Grail Query API (Logs on Grail)",
        "deprecated_since": "SaaS 1.280 / Managed 1.284",
        "eol": "End of 2027",
        "severity": "MEDIUM",
    },
    "/api/v2/logs/export": {
        "replacement": "Grail Query API (Logs on Grail)",
        "deprecated_since": "SaaS 1.280 / Managed 1.284",
        "eol": "End of 2027",
        "severity": "MEDIUM",
    },
    "/api/v2/logs/aggregate": {
        "replacement": "Grail Query API (Logs on Grail)",
        "deprecated_since": "SaaS 1.280 / Managed 1.284",
        "eol": "End of 2027",
        "severity": "MEDIUM",
    },
    # Settings 2.0 migrations
    "/api/config/v1/autoTags": {
        "replacement": "/api/v2/settings (schema: builtin:tags.auto-tagging)",
        "deprecated_since": "Settings 2.0 migration",
        "eol": "TBD",
        "severity": "MEDIUM",
    },
    "/api/config/v1/alertingProfiles": {
        "replacement": "/api/v2/settings (schema: builtin:alerting.profile)",
        "deprecated_since": "Settings 2.0 migration",
        "eol": "TBD",
        "severity": "MEDIUM",
    },
    "/api/config/v1/notifications": {
        "replacement": "/api/v2/settings (schema: builtin:problem.notifications)",
        "deprecated_since": "Settings 2.0 migration",
        "eol": "TBD",
        "severity": "MEDIUM",
    },
    "/api/config/v1/managementZones": {
        "replacement": "/api/v2/settings (schema: builtin:management-zones)",
        "deprecated_since": "Settings 2.0 migration",
        "eol": "TBD",
        "severity": "MEDIUM",
    },
    "/api/config/v1/requestAttributes": {
        "replacement": "/api/v2/settings (schema: builtin:request-attributes)",
        "deprecated_since": "Settings 2.0 migration",
        "eol": "TBD",
        "severity": "LOW",
    },
}

# Token scopes needed for comprehensive audit
REQUIRED_SCOPES = [
    "entities.read",
    "metrics.read",
    "problems.read",
    "settings.read",
    "events.read",
    "activeGates.read",
    "slo.read",
    "oneAgents.read",
    "auditLogs.read",
    "networkZones.read",
    "extensions.read",
]

# Key entity types for Smartscape-like topology
SMARTSCAPE_ENTITY_TYPES = [
    "HOST",
    "PROCESS_GROUP",
    "PROCESS_GROUP_INSTANCE",
    "SERVICE",
    "APPLICATION",
    "HTTP_CHECK",
    "BROWSER_MONITOR",
    "SYNTHETIC_TEST",
    "KUBERNETES_CLUSTER",
    "CLOUD_APPLICATION",
    "CLOUD_APPLICATION_NAMESPACE",
]

# Color palette (Dynatrace-inspired)
DT_PURPLE = "#6F2DA8"
DT_BLUE = "#1496FF"
DT_GREEN = "#2AB06F"
DT_RED = "#DC172A"
DT_ORANGE = "#FF6A00"
DT_GRAY = "#B4B4B4"
DT_DARK = "#1A1A2E"

# ═══════════════════════════════════════════════════════════════════
#  CONFIG LOADER
# ═══════════════════════════════════════════════════════════════════

DEFAULT_CONFIG_TEMPLATE = """# ──────────────────────────────────────────────
# Dynatrace Multi-Environment Analyzer Config
# ──────────────────────────────────────────────
# Rename this file to config.yaml and fill in your details.

environments:
  - name: "PROD"
    url: "https://abc12345.live.dynatrace.com"   # No trailing slash
    token: "dt0c01.XXXXXXXX.YYYYYYYYYYYYYYYY"
    type: "SaaS"           # SaaS | Managed

  - name: "NON-PROD"
    url: "https://def67890.live.dynatrace.com"
    token: "dt0c01.XXXXXXXX.YYYYYYYYYYYYYYYY"
    type: "SaaS"

  - name: "DR"
    url: "https://ghi11223.live.dynatrace.com"
    token: "dt0c01.XXXXXXXX.YYYYYYYYYYYYYYYY"
    type: "SaaS"

settings:
  timeout_seconds: 30
  max_retries: 3
  rate_limit_pause: 0.25       # seconds between API calls
  lookback_days: 30            # for problems/events analysis
  output_dir: "./dt_reports"
"""


def load_config(config_path: str) -> dict:
    """Load and validate YAML configuration."""
    path = Path(config_path)
    if not path.exists():
        # Generate template
        template_path = path.with_suffix(".yaml.template")
        template_path.write_text(DEFAULT_CONFIG_TEMPLATE)
        log.error(f"Config file not found: {config_path}")
        log.info(f"Template created at: {template_path}")
        log.info("Fill in your Dynatrace environment details and rename to config.yaml")
        sys.exit(1)

    with open(path) as f:
        cfg = yaml.safe_load(f)

    # Validate
    if "environments" not in cfg or len(cfg["environments"]) == 0:
        log.error("No environments defined in config.")
        sys.exit(1)

    for env in cfg["environments"]:
        for key in ("name", "url", "token"):
            if key not in env or not env[key]:
                log.error(f"Missing '{key}' in environment config: {env}")
                sys.exit(1)
        # Strip trailing slash
        env["url"] = env["url"].rstrip("/")

    return cfg


# ═══════════════════════════════════════════════════════════════════
#  DYNATRACE API CLIENT
# ═══════════════════════════════════════════════════════════════════

class DynatraceClient:
    """Robust Dynatrace API v2 client with pagination, retry, and rate-limit handling."""

    def __init__(self, name: str, url: str, token: str, env_type: str = "SaaS",
                 timeout: int = 30, max_retries: int = 3, rate_pause: float = 0.25):
        self.name = name
        self.base_url = url
        self.token = token
        self.env_type = env_type
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_pause = rate_pause
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Api-Token {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self._call_count = 0

    def _request(self, method: str, endpoint: str, params: dict = None,
                 json_body: dict = None) -> Optional[dict]:
        """Make an API request with retry logic."""
        url = f"{self.base_url}{endpoint}"
        for attempt in range(1, self.max_retries + 1):
            try:
                time.sleep(self.rate_pause)
                self._call_count += 1
                resp = self.session.request(
                    method, url, params=params, json=json_body, timeout=self.timeout
                )
                if resp.status_code == 429:
                    wait = int(resp.headers.get("Retry-After", 5))
                    log.warning(f"[{self.name}] Rate limited. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                if resp.status_code == 401:
                    log.error(f"[{self.name}] Authentication failed for {endpoint}. Check token scopes.")
                    return None
                if resp.status_code == 403:
                    log.warning(f"[{self.name}] Forbidden: {endpoint}. Missing scope.")
                    return None
                if resp.status_code == 404:
                    log.debug(f"[{self.name}] Not found: {endpoint}")
                    return None
                resp.raise_for_status()
                if resp.text:
                    return resp.json()
                return {}
            except requests.exceptions.Timeout:
                log.warning(f"[{self.name}] Timeout on {endpoint} (attempt {attempt})")
            except requests.exceptions.ConnectionError:
                log.warning(f"[{self.name}] Connection error on {endpoint} (attempt {attempt})")
            except requests.exceptions.HTTPError as e:
                log.warning(f"[{self.name}] HTTP error {e} on {endpoint}")
                return None
            except Exception as e:
                log.error(f"[{self.name}] Unexpected error on {endpoint}: {e}")
                return None
        log.error(f"[{self.name}] Failed after {self.max_retries} retries: {endpoint}")
        return None

    def get(self, endpoint: str, params: dict = None) -> Optional[dict]:
        return self._request("GET", endpoint, params=params)

    def get_paginated(self, endpoint: str, params: dict = None,
                      items_key: str = None) -> List[dict]:
        """Fetch all pages of a paginated v2 endpoint."""
        all_items = []
        params = params or {}

        resp = self.get(endpoint, params)
        if resp is None:
            return all_items

        # Auto-detect items key
        if items_key is None:
            for candidate in ("entities", "metrics", "records", "problems",
                              "events", "results", "objects", "activeGates",
                              "tokens", "slo", "extensions", "monitors",
                              "networkZones", "hosts", "auditLogs"):
                if candidate in resp:
                    items_key = candidate
                    break
            if items_key is None:
                # Return raw response in list
                return [resp]

        all_items.extend(resp.get(items_key, []))
        # Follow pagination
        while resp and resp.get("nextPageKey"):
            next_params = {**params, "nextPageKey": resp["nextPageKey"]}
            # Remove other params on subsequent pages per Dynatrace docs
            for k in list(next_params.keys()):
                if k not in ("nextPageKey", "pageSize"):
                    pass  # keep them; v2 ignores extras
            resp = self.get(endpoint, next_params)
            if resp and items_key in resp:
                all_items.extend(resp[items_key])
        return all_items

    # ── High-level data collectors ─────────────────────────────────

    def get_cluster_version(self) -> Optional[str]:
        resp = self.get("/api/v1/config/clusterversion")
        if resp:
            return resp.get("version", "unknown")
        return None

    def get_entities_by_type(self, entity_type: str, fields: str = "+properties,+tags,+managementZones,+fromRelationships,+toRelationships") -> List[dict]:
        params = {
            "entitySelector": f'type("{entity_type}")',
            "fields": fields,
            "pageSize": 500,
            "from": "now-72h",
        }
        return self.get_paginated("/api/v2/entities", params, items_key="entities")

    def get_all_entity_types(self) -> List[dict]:
        return self.get_paginated("/api/v2/entityTypes", {"pageSize": 500}, items_key="types")

    def get_problems(self, days_back: int = 30) -> List[dict]:
        params = {
            "from": f"now-{days_back}d",
            "pageSize": 500,
            "fields": "+evidenceDetails,+impactAnalysis",
        }
        return self.get_paginated("/api/v2/problems", params, items_key="problems")

    def get_settings(self, schema_id: str) -> List[dict]:
        params = {"schemaIds": schema_id, "pageSize": 500}
        return self.get_paginated("/api/v2/settings/objects", params, items_key="items")

    def get_active_gates(self) -> List[dict]:
        return self.get_paginated("/api/v2/activeGates", {"pageSize": 500}, items_key="activeGates")

    def get_oneagents(self) -> List[dict]:
        params = {"pageSize": 500}
        return self.get_paginated("/api/v2/oneAgents", params)

    def get_slos(self) -> List[dict]:
        params = {
            "pageSize": 100,
            "timeFrame": "CURRENT",
            "evaluate": "true",
        }
        return self.get_paginated("/api/v2/slo", params, items_key="slo")

    def get_extensions(self) -> List[dict]:
        return self.get_paginated("/api/v2/extensions", {"pageSize": 100}, items_key="extensions")

    def get_network_zones(self) -> List[dict]:
        resp = self.get("/api/v2/networkZones")
        if resp and "networkZones" in resp:
            return resp["networkZones"]
        return []

    def get_synthetic_monitors(self) -> List[dict]:
        return self.get_paginated("/api/v2/synthetic/monitors", {"pageSize": 500}, items_key="monitors")

    def get_audit_logs(self, days_back: int = 30) -> List[dict]:
        params = {
            "from": f"now-{days_back}d",
            "pageSize": 500,
            "filter": 'category("CONFIG")',
        }
        return self.get_paginated("/api/v2/auditlogs", params, items_key="auditLogs")

    def get_alerting_profiles(self) -> List[dict]:
        return self.get_settings("builtin:alerting.profile")

    def get_notification_rules(self) -> List[dict]:
        return self.get_settings("builtin:problem.notifications")

    def get_maintenance_windows(self) -> List[dict]:
        return self.get_settings("builtin:alerting.maintenance-window")

    def get_management_zones(self) -> List[dict]:
        return self.get_settings("builtin:management-zones")

    def get_auto_tags(self) -> List[dict]:
        return self.get_settings("builtin:tags.auto-tagging")

    def check_deprecated_v1_access(self) -> Dict[str, Any]:
        """Probe deprecated v1 endpoints to see if they still respond."""
        results = {}
        test_endpoints = {
            "/api/v1/timeseries": "Timeseries API v1",
            "/api/v1/entity/infrastructure/hosts": "Topology & Smartscape (Hosts)",
            "/api/v1/entity/services": "Topology & Smartscape (Services)",
            "/api/v1/problem/feed": "Problems API v1",
            "/api/v1/events": "Events API v1",
        }
        for endpoint, name in test_endpoints.items():
            resp = self.get(endpoint, params={"relativeTime": "hour"})
            results[endpoint] = {
                "name": name,
                "accessible": resp is not None,
                "info": DEPRECATED_API_MAP.get(endpoint.split("?")[0], {}),
            }
        return results

    def validate_token_scopes(self) -> Dict[str, bool]:
        """Check which scopes the current token has."""
        scope_check = {}
        test_map = {
            "entities.read": ("/api/v2/entities", {"entitySelector": 'type("HOST")', "pageSize": 1}),
            "metrics.read": ("/api/v2/metrics", {"pageSize": 1}),
            "problems.read": ("/api/v2/problems", {"pageSize": 1}),
            "settings.read": ("/api/v2/settings/objects", {"schemaIds": "builtin:alerting.profile", "pageSize": 1}),
            "activeGates.read": ("/api/v2/activeGates", {"pageSize": 1}),
            "slo.read": ("/api/v2/slo", {"pageSize": 1}),
            "oneAgents.read": ("/api/v2/oneAgents", {"pageSize": 1}),
            "extensions.read": ("/api/v2/extensions", {"pageSize": 1}),
        }
        for scope, (endpoint, params) in test_map.items():
            resp = self.get(endpoint, params)
            scope_check[scope] = resp is not None
        return scope_check


# ═══════════════════════════════════════════════════════════════════
#  ENVIRONMENT ANALYZER
# ═══════════════════════════════════════════════════════════════════

class EnvironmentAnalyzer:
    """Performs comprehensive analysis on a single Dynatrace environment."""

    def __init__(self, client: DynatraceClient, lookback_days: int = 30):
        self.client = client
        self.lookback_days = lookback_days
        self.data: Dict[str, Any] = {}
        self.gaps: List[Dict[str, str]] = []
        self.recommendations: List[Dict[str, str]] = []

    def run_full_analysis(self) -> Dict[str, Any]:
        log.info(f"═══ Analyzing environment: {self.client.name} ═══")

        # 1. Cluster version
        log.info(f"[{self.client.name}] Fetching cluster version...")
        self.data["version"] = self.client.get_cluster_version()
        log.info(f"[{self.client.name}] Version: {self.data['version']}")

        # 2. Token scope validation
        log.info(f"[{self.client.name}] Validating token scopes...")
        self.data["scopes"] = self.client.validate_token_scopes()
        missing = [s for s, ok in self.data["scopes"].items() if not ok]
        if missing:
            self.gaps.append({
                "category": "Security",
                "severity": "HIGH",
                "finding": f"Token missing scopes: {', '.join(missing)}",
                "impact": "Incomplete audit — some data inaccessible",
            })

        # 3. Entities (Smartscape topology)
        log.info(f"[{self.client.name}] Collecting entity topology...")
        self.data["entities"] = {}
        entity_counts = {}
        for etype in SMARTSCAPE_ENTITY_TYPES:
            entities = self.client.get_entities_by_type(etype)
            self.data["entities"][etype] = entities
            entity_counts[etype] = len(entities)
            log.info(f"[{self.client.name}]   {etype}: {len(entities)} entities")

        self.data["entity_counts"] = entity_counts

        # 4. Problems analysis
        log.info(f"[{self.client.name}] Fetching problems ({self.lookback_days}d)...")
        self.data["problems"] = self.client.get_problems(self.lookback_days)
        log.info(f"[{self.client.name}]   {len(self.data['problems'])} problems found")
        self._analyze_problems()

        # 5. ActiveGates
        log.info(f"[{self.client.name}] Fetching ActiveGates...")
        self.data["activegates"] = self.client.get_active_gates()
        log.info(f"[{self.client.name}]   {len(self.data['activegates'])} ActiveGates")
        self._analyze_activegates()

        # 6. Management Zones
        log.info(f"[{self.client.name}] Fetching Management Zones...")
        self.data["mgmt_zones"] = self.client.get_management_zones()

        # 7. Auto-Tags
        log.info(f"[{self.client.name}] Fetching Auto-Tag rules...")
        self.data["auto_tags"] = self.client.get_auto_tags()

        # 8. Alerting Profiles & Notifications
        log.info(f"[{self.client.name}] Fetching Alerting config...")
        self.data["alerting_profiles"] = self.client.get_alerting_profiles()
        self.data["notifications"] = self.client.get_notification_rules()
        self._analyze_alerting()

        # 9. Maintenance Windows
        log.info(f"[{self.client.name}] Fetching Maintenance Windows...")
        self.data["maintenance_windows"] = self.client.get_maintenance_windows()

        # 10. SLOs
        log.info(f"[{self.client.name}] Fetching SLOs...")
        self.data["slos"] = self.client.get_slos()
        self._analyze_slos()

        # 11. Extensions
        log.info(f"[{self.client.name}] Fetching Extensions 2.0...")
        self.data["extensions"] = self.client.get_extensions()

        # 12. Synthetic Monitors
        log.info(f"[{self.client.name}] Fetching Synthetic Monitors...")
        self.data["synthetic"] = self.client.get_synthetic_monitors()

        # 13. Network Zones
        log.info(f"[{self.client.name}] Fetching Network Zones...")
        self.data["network_zones"] = self.client.get_network_zones()

        # 14. Deprecated API probe
        log.info(f"[{self.client.name}] Probing deprecated v1 endpoints...")
        self.data["deprecated_apis"] = self.client.check_deprecated_v1_access()
        self._analyze_deprecated_apis()

        # 15. OneAgent analysis
        log.info(f"[{self.client.name}] Fetching OneAgent info...")
        self.data["oneagents"] = self.client.get_oneagents()
        self._analyze_oneagents()

        # 16. Gap analysis for observability coverage
        self._run_gap_analysis()

        log.info(f"[{self.client.name}] Analysis complete. "
                 f"{len(self.gaps)} gaps, {len(self.recommendations)} recommendations. "
                 f"API calls: {self.client._call_count}")

        return {
            "name": self.client.name,
            "url": self.client.base_url,
            "type": self.client.env_type,
            "data": self.data,
            "gaps": self.gaps,
            "recommendations": self.recommendations,
            "api_calls": self.client._call_count,
        }

    # ── Sub-analyzers ──────────────────────────────────────────────

    def _analyze_problems(self):
        problems = self.data.get("problems", [])
        if not problems:
            return
        status_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        for p in problems:
            status_counts[p.get("status", "UNKNOWN")] += 1
            severity_counts[p.get("severityLevel", "UNKNOWN")] += 1
        self.data["problem_stats"] = {
            "total": len(problems),
            "by_status": dict(status_counts),
            "by_severity": dict(severity_counts),
        }
        open_count = status_counts.get("OPEN", 0)
        if open_count > 20:
            self.gaps.append({
                "category": "Problem Management",
                "severity": "HIGH",
                "finding": f"{open_count} open problems — noise or unresolved issues",
                "impact": "Alert fatigue, missed critical issues in GxP environment",
            })
            self.recommendations.append({
                "category": "Problem Management",
                "priority": "P1",
                "action": "Implement problem noise-reduction: tune anomaly detection thresholds, "
                          "create Davis AI-driven baselines, review alerting profiles",
                "effort": "Medium",
            })

    def _analyze_activegates(self):
        ags = self.data.get("activegates", [])
        if not ags:
            self.gaps.append({
                "category": "Infrastructure",
                "severity": "MEDIUM",
                "finding": "No ActiveGates detected (or no read access)",
                "impact": "Cannot verify AG health, version, or routing",
            })
            return
        outdated = []
        for ag in ags:
            ver = ag.get("version", "")
            modules = ag.get("modules", [])
            if ag.get("autoUpdateStatus") == "OUTDATED":
                outdated.append(ag.get("hostname", "unknown"))
        if outdated:
            self.gaps.append({
                "category": "Infrastructure",
                "severity": "HIGH",
                "finding": f"{len(outdated)} ActiveGate(s) running outdated versions",
                "impact": "Security risk, missing latest features & patches",
            })
            self.recommendations.append({
                "category": "Infrastructure",
                "priority": "P1",
                "action": f"Update ActiveGates: {', '.join(outdated[:5])}{'...' if len(outdated)>5 else ''}",
                "effort": "Low",
            })

    def _analyze_alerting(self):
        profiles = self.data.get("alerting_profiles", [])
        notifications = self.data.get("notifications", [])
        if not profiles:
            self.gaps.append({
                "category": "Alerting",
                "severity": "HIGH",
                "finding": "No alerting profiles configured (or inaccessible)",
                "impact": "Default alerting may cause noise; no severity filtering",
            })
        if not notifications:
            self.gaps.append({
                "category": "Alerting",
                "severity": "CRITICAL",
                "finding": "No notification rules configured",
                "impact": "Problems detected but nobody is notified — silent failures",
            })
            self.recommendations.append({
                "category": "Alerting",
                "priority": "P0",
                "action": "Configure notification integrations (PagerDuty, ServiceNow, email) "
                          "with proper routing and escalation",
                "effort": "Medium",
            })

    def _analyze_slos(self):
        slos = self.data.get("slos", [])
        if not slos:
            self.gaps.append({
                "category": "SLO / SRE",
                "severity": "MEDIUM",
                "finding": "No SLOs defined in this environment",
                "impact": "No measurable reliability targets — weak SRE posture",
            })
            self.recommendations.append({
                "category": "SLO / SRE",
                "priority": "P2",
                "action": "Define SLOs for critical services (availability, error rate, "
                          "response time). Start with golden signals.",
                "effort": "Medium",
            })
        else:
            breached = [s for s in slos if s.get("evaluatedPercentage", 100) < s.get("target", 99)]
            if breached:
                self.gaps.append({
                    "category": "SLO / SRE",
                    "severity": "HIGH",
                    "finding": f"{len(breached)} SLO(s) currently breaching target",
                    "impact": "Reliability targets not being met",
                })

    def _analyze_deprecated_apis(self):
        dep = self.data.get("deprecated_apis", {})
        for endpoint, info in dep.items():
            if info.get("accessible"):
                api_info = info.get("info", {})
                self.gaps.append({
                    "category": "API Deprecation",
                    "severity": api_info.get("severity", "MEDIUM"),
                    "finding": f"Deprecated endpoint still accessible: {endpoint}",
                    "impact": f"EOL: {api_info.get('eol', 'TBD')} — migrate to {api_info.get('replacement', 'v2 equivalent')}",
                })
        # Always recommend migration check
        self.recommendations.append({
            "category": "API Deprecation",
            "priority": "P1",
            "action": "Audit all automation scripts and integrations for v1 API usage. "
                      "Migrate Timeseries→Metrics v2, Topology→Entities v2, "
                      "Problems v1→v2, Events v1→v2, Config v1→Settings 2.0.",
            "effort": "High",
        })

    def _analyze_oneagents(self):
        agents = self.data.get("oneagents", [])
        if isinstance(agents, list) and len(agents) > 0:
            # Check for items that may be dicts
            outdated = []
            for a in agents:
                if isinstance(a, dict):
                    status = a.get("updateStatus", "")
                    if status in ("OUTDATED", "SUPPRESSED"):
                        host_info = a.get("hostInfo", {})
                        outdated.append(host_info.get("displayName", "unknown"))
            if outdated:
                self.gaps.append({
                    "category": "Agent Management",
                    "severity": "HIGH",
                    "finding": f"{len(outdated)} OneAgent(s) outdated or update-suppressed",
                    "impact": "Missing security patches and new features",
                })
                self.recommendations.append({
                    "category": "Agent Management",
                    "priority": "P1",
                    "action": "Enable OneAgent auto-update or schedule update windows "
                              "for outdated agents in compliance with GxP change control",
                    "effort": "Medium",
                })

    def _run_gap_analysis(self):
        """Cross-cutting observability gap analysis."""
        ec = self.data.get("entity_counts", {})

        # No hosts monitored
        if ec.get("HOST", 0) == 0:
            self.gaps.append({
                "category": "Coverage",
                "severity": "CRITICAL",
                "finding": "No hosts detected — infrastructure monitoring gap",
                "impact": "Zero visibility into server health",
            })

        # Services but no applications
        if ec.get("SERVICE", 0) > 0 and ec.get("APPLICATION", 0) == 0:
            self.gaps.append({
                "category": "Coverage",
                "severity": "MEDIUM",
                "finding": "Services monitored but no RUM/Applications configured",
                "impact": "No end-user experience visibility",
            })
            self.recommendations.append({
                "category": "Coverage",
                "priority": "P2",
                "action": "Enable Real User Monitoring (RUM) for web applications "
                          "to capture user experience metrics",
                "effort": "Low",
            })

        # No synthetic monitoring
        if ec.get("HTTP_CHECK", 0) == 0 and ec.get("BROWSER_MONITOR", 0) == 0:
            self.gaps.append({
                "category": "Coverage",
                "severity": "MEDIUM",
                "finding": "No synthetic monitors configured",
                "impact": "No proactive availability monitoring",
            })
            self.recommendations.append({
                "category": "Coverage",
                "priority": "P2",
                "action": "Set up HTTP check monitors for critical endpoints "
                          "and browser-click monitors for key user journeys",
                "effort": "Medium",
            })

        # Management zones
        mz = self.data.get("mgmt_zones", [])
        if not mz:
            self.gaps.append({
                "category": "Governance",
                "severity": "MEDIUM",
                "finding": "No management zones defined",
                "impact": "No data segmentation — everyone sees everything (RBAC gap in GxP)",
            })
            self.recommendations.append({
                "category": "Governance",
                "priority": "P1",
                "action": "Define management zones aligned to application tiers, "
                          "business units, or GxP validation boundaries",
                "effort": "Medium",
            })

        # Auto-tags
        tags = self.data.get("auto_tags", [])
        if len(tags) < 3:
            self.recommendations.append({
                "category": "Governance",
                "priority": "P2",
                "action": "Implement auto-tagging strategy: environment, tier, owner, "
                          "cost-center, GxP-classification tags",
                "effort": "Medium",
            })

        # Network zones
        nz = self.data.get("network_zones", [])
        if not nz:
            self.recommendations.append({
                "category": "Network",
                "priority": "P3",
                "action": "Consider network zones for segmented traffic routing "
                          "through ActiveGates (useful for DMZ/airgapped segments)",
                "effort": "Low",
            })


# ═══════════════════════════════════════════════════════════════════
#  SMARTSCAPE DIAGRAM GENERATOR
# ═══════════════════════════════════════════════════════════════════

class SmartscapeDiagram:
    """Generates a Smartscape-like architecture diagram using Graphviz."""

    LAYER_CONFIG = {
        "APPLICATION":    {"rank": 0, "color": "#6F2DA8", "shape": "doubleoctagon", "label": "Applications"},
        "SERVICE":        {"rank": 1, "color": "#1496FF", "shape": "component",     "label": "Services"},
        "PROCESS_GROUP":  {"rank": 2, "color": "#2AB06F", "shape": "box3d",         "label": "Process Groups"},
        "HOST":           {"rank": 3, "color": "#FF6A00", "shape": "box",           "label": "Hosts"},
        "KUBERNETES_CLUSTER": {"rank": 3, "color": "#326CE5", "shape": "tab",       "label": "K8s Clusters"},
    }

    def __init__(self, env_name: str, entities: Dict[str, List[dict]], output_dir: str):
        self.env_name = env_name
        self.entities = entities
        self.output_dir = output_dir

    def generate(self) -> Optional[str]:
        """Generate Smartscape diagram and return the file path."""
        dot = graphviz.Digraph(
            name=f"smartscape_{self.env_name}",
            format="png",
            engine="dot",
        )
        dot.attr(
            rankdir="TB",
            bgcolor="#1A1A2E",
            fontcolor="white",
            fontname="Helvetica",
            label=f"Smartscape Topology — {self.env_name}",
            labelloc="t",
            fontsize="20",
            pad="0.5",
            nodesep="0.4",
            ranksep="0.8",
            dpi="150",
        )
        dot.attr("node", fontname="Helvetica", fontsize="9", fontcolor="white", style="filled")
        dot.attr("edge", color="#555555", arrowsize="0.6", penwidth="0.8")

        entity_id_map = {}  # entityId → node_id

        # Build nodes per layer
        for etype, config in self.LAYER_CONFIG.items():
            items = self.entities.get(etype, [])
            if not items:
                continue

            # Limit display to top 30 per layer for readability
            display_items = items[:30]
            overflow = len(items) - len(display_items)

            with dot.subgraph(name=f"cluster_{etype}") as sub:
                sub.attr(
                    label=f"{config['label']} ({len(items)})",
                    style="dashed",
                    color=config["color"],
                    fontcolor=config["color"],
                    fontsize="12",
                )

                for entity in display_items:
                    eid = entity.get("entityId", "")
                    name = entity.get("displayName", eid)[:40]
                    node_id = eid.replace("-", "_").replace(".", "_")
                    entity_id_map[eid] = node_id

                    # Truncate long names
                    label = name if len(name) <= 30 else name[:27] + "..."

                    sub.node(
                        node_id,
                        label=label,
                        shape=config["shape"],
                        fillcolor=config["color"],
                        color=config["color"],
                    )

                if overflow > 0:
                    sub.node(
                        f"overflow_{etype}",
                        label=f"... +{overflow} more",
                        shape="plaintext",
                        fontcolor=config["color"],
                        fillcolor="#1A1A2E",
                    )

        # Build edges from relationships
        edge_count = 0
        max_edges = 200  # Cap for readability
        for etype, items in self.entities.items():
            for entity in items:
                eid = entity.get("entityId", "")
                src = entity_id_map.get(eid)
                if not src:
                    continue
                # "calls" and "runsOn" relationships
                for rel_type in ("calls", "runsOn", "isProcessOf", "runs", "contains"):
                    rels = entity.get("fromRelationships", {}).get(rel_type, [])
                    for rel in rels:
                        target_id = rel.get("id", "") if isinstance(rel, dict) else rel
                        tgt = entity_id_map.get(target_id)
                        if tgt and edge_count < max_edges:
                            dot.edge(src, tgt, color="#555555AA")
                            edge_count += 1

        # Render
        try:
            output_path = os.path.join(self.output_dir, f"smartscape_{self.env_name}")
            dot.render(output_path, cleanup=True)
            log.info(f"[{self.env_name}] Smartscape diagram saved: {output_path}.png")
            return f"{output_path}.png"
        except Exception as e:
            log.error(f"[{self.env_name}] Diagram generation failed: {e}")
            return None


# ═══════════════════════════════════════════════════════════════════
#  PDF REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Generates a comprehensive PDF report with all findings."""

    def __init__(self, results: List[dict], output_path: str, diagrams: Dict[str, str]):
        self.results = results
        self.output_path = output_path
        self.diagrams = diagrams
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        self.styles.add(ParagraphStyle(
            "CoverTitle", parent=self.styles["Title"],
            fontSize=28, textColor=colors.HexColor(DT_PURPLE),
            spaceAfter=20, alignment=TA_CENTER,
        ))
        self.styles.add(ParagraphStyle(
            "CoverSub", parent=self.styles["Normal"],
            fontSize=14, textColor=colors.HexColor("#666666"),
            alignment=TA_CENTER, spaceAfter=10,
        ))
        self.styles.add(ParagraphStyle(
            "SectionHead", parent=self.styles["Heading1"],
            fontSize=16, textColor=colors.HexColor(DT_PURPLE),
            spaceBefore=16, spaceAfter=8,
        ))
        self.styles.add(ParagraphStyle(
            "SubSection", parent=self.styles["Heading2"],
            fontSize=13, textColor=colors.HexColor(DT_BLUE),
            spaceBefore=10, spaceAfter=6,
        ))
        self.styles.add(ParagraphStyle(
            "BodyText2", parent=self.styles["Normal"],
            fontSize=9, leading=12, spaceAfter=4,
        ))
        self.styles.add(ParagraphStyle(
            "SmallNote", parent=self.styles["Normal"],
            fontSize=7, textColor=colors.HexColor("#999999"),
        ))
        self.styles.add(ParagraphStyle(
            "CellText", parent=self.styles["Normal"],
            fontSize=8, leading=10,
        ))

    def generate(self):
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=A4,
            topMargin=20*mm,
            bottomMargin=20*mm,
            leftMargin=15*mm,
            rightMargin=15*mm,
        )
        story = []

        # ── Cover Page ─────────────────────────────────────────
        story.append(Spacer(1, 80))
        story.append(Paragraph("Dynatrace Environment", self.styles["CoverTitle"]))
        story.append(Paragraph("Comprehensive Analysis Report", self.styles["CoverTitle"]))
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="60%", color=colors.HexColor(DT_PURPLE), thickness=2))
        story.append(Spacer(1, 20))

        env_names = [r["name"] for r in self.results]
        story.append(Paragraph(f"Environments: {' | '.join(env_names)}", self.styles["CoverSub"]))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}",
            self.styles["CoverSub"]
        ))
        story.append(Paragraph("Monitoring Admin — Observability Operations", self.styles["CoverSub"]))
        story.append(Spacer(1, 30))

        # API deprecation reference summary
        story.append(Paragraph(
            "Covers: Entity Topology, Problem Analysis, Alerting Config, SLOs, "
            "ActiveGates, OneAgents, Deprecated API Audit, Extensions, Synthetic Monitors, "
            "Management Zones, Auto-Tags, Network Zones, and Observability Gap Analysis.",
            self.styles["BodyText2"]
        ))
        story.append(PageBreak())

        # ── Table of Contents (manual) ─────────────────────────
        story.append(Paragraph("Table of Contents", self.styles["SectionHead"]))
        toc_items = [
            "1. Executive Summary",
            "2. Environment Overview & Entity Counts",
            "3. Smartscape Topology Diagrams",
            "4. Deprecated API Audit",
            "5. Problem & Event Analysis",
            "6. Alerting & Notification Config",
            "7. SLO Assessment",
            "8. Infrastructure Health (ActiveGates & OneAgents)",
            "9. Governance (Mgmt Zones, Auto-Tags, Network Zones)",
            "10. Gap Analysis — Consolidated Findings",
            "11. Recommendations — Prioritized Action Plan",
            "12. Appendix — Token Scopes & Deprecated API Reference",
        ]
        for item in toc_items:
            story.append(Paragraph(item, self.styles["BodyText2"]))
        story.append(PageBreak())

        # ── 1. Executive Summary ───────────────────────────────
        story.append(Paragraph("1. Executive Summary", self.styles["SectionHead"]))
        total_gaps = sum(len(r["gaps"]) for r in self.results)
        total_recs = sum(len(r["recommendations"]) for r in self.results)
        critical_gaps = sum(1 for r in self.results for g in r["gaps"] if g["severity"] == "CRITICAL")
        high_gaps = sum(1 for r in self.results for g in r["gaps"] if g["severity"] == "HIGH")

        summary_data = [
            ["Metric", "Value"],
            ["Environments Analyzed", str(len(self.results))],
            ["Total Gaps Found", str(total_gaps)],
            ["Critical Gaps", str(critical_gaps)],
            ["High Severity Gaps", str(high_gaps)],
            ["Total Recommendations", str(total_recs)],
        ]
        for r in self.results:
            ec = r["data"].get("entity_counts", {})
            total_entities = sum(ec.values())
            summary_data.append([f"{r['name']} — Monitored Entities", str(total_entities)])
            summary_data.append([f"{r['name']} — Open Problems",
                                 str(r["data"].get("problem_stats", {}).get("by_status", {}).get("OPEN", 0))])

        story.append(self._make_table(summary_data, col_widths=[250, 200]))
        story.append(Spacer(1, 10))
        story.append(PageBreak())

        # ── 2. Environment Overview ────────────────────────────
        story.append(Paragraph("2. Environment Overview & Entity Counts", self.styles["SectionHead"]))
        for r in self.results:
            story.append(Paragraph(f"{r['name']} ({r['type']})", self.styles["SubSection"]))
            story.append(Paragraph(f"URL: {r['url']}", self.styles["SmallNote"]))
            story.append(Paragraph(f"Cluster Version: {r['data'].get('version', 'N/A')}", self.styles["BodyText2"]))

            ec = r["data"].get("entity_counts", {})
            if ec:
                rows = [["Entity Type", "Count"]]
                for etype, count in sorted(ec.items(), key=lambda x: -x[1]):
                    rows.append([etype, str(count)])
                story.append(self._make_table(rows, col_widths=[280, 100]))
            story.append(Spacer(1, 10))
        story.append(PageBreak())

        # ── 3. Smartscape Diagrams ─────────────────────────────
        story.append(Paragraph("3. Smartscape Topology Diagrams", self.styles["SectionHead"]))
        for env_name, diagram_path in self.diagrams.items():
            if diagram_path and os.path.exists(diagram_path):
                story.append(Paragraph(f"Topology — {env_name}", self.styles["SubSection"]))
                try:
                    img = Image(diagram_path)
                    # Scale to fit page width
                    max_width = 500
                    max_height = 600
                    w, h = img.imageWidth, img.imageHeight
                    if w > 0 and h > 0:
                        ratio = min(max_width / w, max_height / h)
                        img.drawWidth = w * ratio
                        img.drawHeight = h * ratio
                    story.append(img)
                except Exception as e:
                    story.append(Paragraph(f"(Diagram could not be embedded: {e})", self.styles["SmallNote"]))
                story.append(Spacer(1, 10))
            else:
                story.append(Paragraph(
                    f"Topology — {env_name}: No entities found or diagram generation failed.",
                    self.styles["BodyText2"]
                ))
        story.append(PageBreak())

        # ── 4. Deprecated API Audit ────────────────────────────
        story.append(Paragraph("4. Deprecated API Audit", self.styles["SectionHead"]))
        story.append(Paragraph(
            "The following deprecated v1 endpoints were probed to determine if they are still "
            "accessible (indicating potential live usage by scripts/integrations).",
            self.styles["BodyText2"]
        ))
        for r in self.results:
            story.append(Paragraph(f"{r['name']}", self.styles["SubSection"]))
            dep = r["data"].get("deprecated_apis", {})
            if dep:
                rows = [["Endpoint", "Status", "Replacement", "EOL"]]
                for ep, info in dep.items():
                    status = "ACCESSIBLE" if info["accessible"] else "Blocked/404"
                    api_info = info.get("info", {})
                    rows.append([
                        ep,
                        status,
                        api_info.get("replacement", "—")[:50],
                        api_info.get("eol", "TBD"),
                    ])
                story.append(self._make_table(rows, col_widths=[150, 70, 180, 60]))
            story.append(Spacer(1, 8))

        # Full deprecation reference
        story.append(Paragraph("Complete Deprecated API Reference", self.styles["SubSection"]))
        dep_rows = [["Deprecated Endpoint", "Replacement", "Since", "EOL", "Severity"]]
        for ep, info in DEPRECATED_API_MAP.items():
            dep_rows.append([
                ep,
                info["replacement"][:45],
                info["deprecated_since"][:20],
                info["eol"],
                info["severity"],
            ])
        story.append(self._make_table(dep_rows, col_widths=[120, 140, 80, 55, 55],
                                       header_color=colors.HexColor("#8B0000")))
        story.append(PageBreak())

        # ── 5. Problem Analysis ────────────────────────────────
        story.append(Paragraph("5. Problem & Event Analysis", self.styles["SectionHead"]))
        for r in self.results:
            story.append(Paragraph(f"{r['name']}", self.styles["SubSection"]))
            ps = r["data"].get("problem_stats", {})
            if ps:
                rows = [["Metric", "Value"]]
                rows.append(["Total Problems (last 30d)", str(ps.get("total", 0))])
                for status, count in ps.get("by_status", {}).items():
                    rows.append([f"  Status: {status}", str(count)])
                for sev, count in ps.get("by_severity", {}).items():
                    rows.append([f"  Severity: {sev}", str(count)])
                story.append(self._make_table(rows, col_widths=[280, 100]))
            else:
                story.append(Paragraph("No problems found in lookback period.", self.styles["BodyText2"]))
            story.append(Spacer(1, 8))
        story.append(PageBreak())

        # ── 6. Alerting Config ─────────────────────────────────
        story.append(Paragraph("6. Alerting & Notification Configuration", self.styles["SectionHead"]))
        for r in self.results:
            story.append(Paragraph(f"{r['name']}", self.styles["SubSection"]))
            ap = r["data"].get("alerting_profiles", [])
            nf = r["data"].get("notifications", [])
            mw = r["data"].get("maintenance_windows", [])
            rows = [["Config Item", "Count"]]
            rows.append(["Alerting Profiles", str(len(ap))])
            rows.append(["Notification Rules", str(len(nf))])
            rows.append(["Maintenance Windows", str(len(mw))])
            story.append(self._make_table(rows, col_widths=[280, 100]))
            story.append(Spacer(1, 8))
        story.append(PageBreak())

        # ── 7. SLO Assessment ──────────────────────────────────
        story.append(Paragraph("7. SLO Assessment", self.styles["SectionHead"]))
        for r in self.results:
            story.append(Paragraph(f"{r['name']}", self.styles["SubSection"]))
            slos = r["data"].get("slos", [])
            if slos:
                rows = [["SLO Name", "Target %", "Actual %", "Status"]]
                for s in slos[:20]:
                    target = s.get("target", "—")
                    actual = s.get("evaluatedPercentage", "—")
                    if isinstance(actual, (int, float)) and isinstance(target, (int, float)):
                        status = "OK" if actual >= target else "BREACHING"
                    else:
                        status = "—"
                    rows.append([
                        str(s.get("name", "unnamed"))[:40],
                        f"{target}",
                        f"{actual:.2f}" if isinstance(actual, float) else str(actual),
                        status,
                    ])
                story.append(self._make_table(rows, col_widths=[180, 70, 70, 70]))
            else:
                story.append(Paragraph("No SLOs configured.", self.styles["BodyText2"]))
            story.append(Spacer(1, 8))
        story.append(PageBreak())

        # ── 8. Infrastructure Health ───────────────────────────
        story.append(Paragraph("8. Infrastructure Health", self.styles["SectionHead"]))
        for r in self.results:
            story.append(Paragraph(f"{r['name']} — ActiveGates", self.styles["SubSection"]))
            ags = r["data"].get("activegates", [])
            if ags:
                rows = [["Hostname", "Version", "OS", "Modules"]]
                for ag in ags[:15]:
                    modules = [m.get("type", "") for m in ag.get("modules", [])]
                    rows.append([
                        str(ag.get("hostname", "—"))[:30],
                        str(ag.get("version", "—"))[:20],
                        str(ag.get("osType", "—")),
                        ", ".join(modules)[:50] if modules else "—",
                    ])
                story.append(self._make_table(rows, col_widths=[120, 80, 60, 180]))
            else:
                story.append(Paragraph("No ActiveGates found.", self.styles["BodyText2"]))

            # Extensions
            story.append(Paragraph(f"{r['name']} — Extensions 2.0", self.styles["SubSection"]))
            exts = r["data"].get("extensions", [])
            if exts:
                rows = [["Extension", "Version"]]
                for ext in exts[:20]:
                    rows.append([
                        str(ext.get("extensionName", "—"))[:50],
                        str(ext.get("version", "—")),
                    ])
                story.append(self._make_table(rows, col_widths=[300, 100]))
            else:
                story.append(Paragraph("No Extensions 2.0 found.", self.styles["BodyText2"]))
            story.append(Spacer(1, 8))
        story.append(PageBreak())

        # ── 9. Governance ──────────────────────────────────────
        story.append(Paragraph("9. Governance", self.styles["SectionHead"]))
        for r in self.results:
            story.append(Paragraph(f"{r['name']}", self.styles["SubSection"]))
            rows = [["Governance Item", "Count"]]
            rows.append(["Management Zones", str(len(r["data"].get("mgmt_zones", [])))])
            rows.append(["Auto-Tag Rules", str(len(r["data"].get("auto_tags", [])))])
            rows.append(["Network Zones", str(len(r["data"].get("network_zones", [])))])
            rows.append(["Synthetic Monitors", str(len(r["data"].get("synthetic", [])))])
            story.append(self._make_table(rows, col_widths=[280, 100]))
            story.append(Spacer(1, 8))
        story.append(PageBreak())

        # ── 10. Gap Analysis ───────────────────────────────────
        story.append(Paragraph("10. Gap Analysis — Consolidated Findings", self.styles["SectionHead"]))
        all_gaps = []
        for r in self.results:
            for g in r["gaps"]:
                all_gaps.append([r["name"], g["severity"], g["category"], g["finding"], g["impact"]])

        if all_gaps:
            # Sort by severity
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            all_gaps.sort(key=lambda x: sev_order.get(x[1], 4))
            rows = [["Env", "Severity", "Category", "Finding", "Impact"]]
            rows.extend(all_gaps)
            story.append(self._make_table(rows, col_widths=[50, 55, 70, 150, 130],
                                           header_color=colors.HexColor("#8B0000")))
        else:
            story.append(Paragraph("No gaps identified — excellent posture!", self.styles["BodyText2"]))
        story.append(PageBreak())

        # ── 11. Recommendations ────────────────────────────────
        story.append(Paragraph("11. Recommendations — Prioritized Action Plan", self.styles["SectionHead"]))
        all_recs = []
        for r in self.results:
            for rec in r["recommendations"]:
                all_recs.append([r["name"], rec["priority"], rec["category"],
                                 rec["action"], rec["effort"]])

        if all_recs:
            pri_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
            all_recs.sort(key=lambda x: pri_order.get(x[1], 4))
            # Deduplicate by action text
            seen = set()
            unique_recs = []
            for rec in all_recs:
                key = rec[3][:80]
                if key not in seen:
                    seen.add(key)
                    unique_recs.append(rec)
            rows = [["Env", "Priority", "Category", "Action", "Effort"]]
            rows.extend(unique_recs)
            story.append(self._make_table(rows, col_widths=[50, 45, 65, 200, 45]))
        story.append(PageBreak())

        # ── 12. Appendix ───────────────────────────────────────
        story.append(Paragraph("12. Appendix — Token Scopes Validation", self.styles["SectionHead"]))
        for r in self.results:
            story.append(Paragraph(f"{r['name']}", self.styles["SubSection"]))
            scopes = r["data"].get("scopes", {})
            if scopes:
                rows = [["Scope", "Status"]]
                for scope, ok in sorted(scopes.items()):
                    rows.append([scope, "OK" if ok else "MISSING / DENIED"])
                story.append(self._make_table(rows, col_widths=[250, 150]))
            story.append(Spacer(1, 8))

        # Footer note
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#CCCCCC"), thickness=0.5))
        story.append(Paragraph(
            "This report was auto-generated by the Dynatrace Multi-Environment Analyzer. "
            "For questions, contact the Observability Operations team.",
            self.styles["SmallNote"]
        ))

        # Build PDF
        doc.build(story)
        log.info(f"PDF report generated: {self.output_path}")

    def _make_table(self, data: List[List], col_widths: List[int] = None,
                    header_color=None) -> Table:
        """Create a styled table from data rows."""
        if header_color is None:
            header_color = colors.HexColor(DT_PURPLE)

        # Wrap cell text in Paragraphs for wrapping
        wrapped = []
        for i, row in enumerate(data):
            wrapped_row = []
            for cell in row:
                style = self.styles["CellText"]
                if i == 0:
                    style = ParagraphStyle("HeaderCell", parent=style,
                                           textColor=colors.white, fontName="Helvetica-Bold")
                wrapped_row.append(Paragraph(str(cell), style))
            wrapped.append(wrapped_row)

        tbl = Table(wrapped, colWidths=col_widths, repeatRows=1)
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), header_color),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5FF")]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]
        tbl.setStyle(TableStyle(style_cmds))
        return tbl


# ═══════════════════════════════════════════════════════════════════
#  MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Dynatrace Multi-Environment Comprehensive Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dt_env_analyzer.py --config config.yaml
  python dt_env_analyzer.py --config config.yaml --output my_report.pdf
  python dt_env_analyzer.py --generate-template
        """
    )
    parser.add_argument("--config", default="config.yaml", help="Path to YAML config file")
    parser.add_argument("--output", default=None, help="Output PDF report path")
    parser.add_argument("--generate-template", action="store_true", help="Generate config template and exit")
    parser.add_argument("--skip-diagrams", action="store_true", help="Skip Smartscape diagram generation")
    parser.add_argument("--lookback", type=int, default=None, help="Override lookback days for problems/events")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.generate_template:
        Path("config.yaml.template").write_text(DEFAULT_CONFIG_TEMPLATE)
        log.info("Template written to config.yaml.template")
        return

    # Load config
    cfg = load_config(args.config)
    settings = cfg.get("settings", {})
    output_dir = settings.get("output_dir", "./dt_reports")
    os.makedirs(output_dir, exist_ok=True)

    lookback = args.lookback or settings.get("lookback_days", 30)
    timeout = settings.get("timeout_seconds", 30)
    retries = settings.get("max_retries", 3)
    rate_pause = settings.get("rate_limit_pause", 0.25)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = args.output or os.path.join(output_dir, f"dt_analysis_{timestamp}.pdf")

    # ── Analyze each environment ───────────────────────────────
    all_results = []
    all_diagrams = {}

    for env_cfg in cfg["environments"]:
        client = DynatraceClient(
            name=env_cfg["name"],
            url=env_cfg["url"],
            token=env_cfg["token"],
            env_type=env_cfg.get("type", "SaaS"),
            timeout=timeout,
            max_retries=retries,
            rate_pause=rate_pause,
        )
        analyzer = EnvironmentAnalyzer(client, lookback_days=lookback)

        try:
            result = analyzer.run_full_analysis()
            all_results.append(result)
        except Exception as e:
            log.error(f"Analysis failed for {env_cfg['name']}: {e}")
            traceback.print_exc()
            all_results.append({
                "name": env_cfg["name"],
                "url": env_cfg["url"],
                "type": env_cfg.get("type", "SaaS"),
                "data": {},
                "gaps": [{"category": "Analysis", "severity": "CRITICAL",
                          "finding": f"Analysis failed: {e}", "impact": "No data collected"}],
                "recommendations": [],
                "api_calls": 0,
            })

        # Generate Smartscape diagram
        if not args.skip_diagrams:
            entities = result.get("data", {}).get("entities", {}) if 'result' in dir() else {}
            if any(len(v) > 0 for v in entities.values()):
                diagram_gen = SmartscapeDiagram(env_cfg["name"], entities, output_dir)
                diagram_path = diagram_gen.generate()
                all_diagrams[env_cfg["name"]] = diagram_path
            else:
                all_diagrams[env_cfg["name"]] = None

    # ── Generate PDF Report ────────────────────────────────────
    log.info("Generating consolidated PDF report...")
    report = ReportGenerator(all_results, output_path, all_diagrams)
    report.generate()

    # ── Summary ────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  ANALYSIS COMPLETE")
    print("=" * 60)
    for r in all_results:
        print(f"\n  {r['name']}:")
        print(f"    Entities: {sum(r['data'].get('entity_counts', {}).values())}")
        print(f"    Gaps:     {len(r['gaps'])}")
        print(f"    Recs:     {len(r['recommendations'])}")
        print(f"    API calls: {r['api_calls']}")
    print(f"\n  Report: {output_path}")
    for name, path in all_diagrams.items():
        if path:
            print(f"  Diagram ({name}): {path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
