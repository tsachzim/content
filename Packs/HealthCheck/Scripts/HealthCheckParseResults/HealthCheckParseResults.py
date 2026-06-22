import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re
from typing import Any

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

ActionItem = dict[str, str]  # keys: category, description, resolution, severity


def make_action_item(
    category: str,
    description: str,
    resolution: str,
    severity: str,
) -> ActionItem:
    """Return a validated ActionItem dict."""
    return {
        "category": category,
        "description": description,
        "resolution": resolution,
        "severity": severity,
    }


# ---------------------------------------------------------------------------
# Threshold configuration
# ---------------------------------------------------------------------------
# Each key is the canonical widget name (must match WIDGET_HANDLERS keys).
# Values are free-form dicts — the handler decides which keys it uses.
# Set threshold values here; action item text lives inside the handler.
#
# Severity levels (convention): "Low" | "Medium" | "High" | "Critical"
# ---------------------------------------------------------------------------

THRESHOLDS: dict[str, dict[str, Any]] = {
    # Agent & Asset
    "AgentPolicyAssignment": {
        # TODO: define threshold — e.g. min number of distinct policies, or
        # flag if any policy has 0 endpoints, etc.
        # "max_policies": 20,
        "severity": "Low",
    },
    "AgentScanStatus": {
        # TODO: define threshold — e.g. flag if IN_PROGRESS count > N
        # "max_in_progress": 5,
        "severity": "Medium",
    },
    "AutoAgentUpgradeStatus": {
        # TODO: define threshold — e.g. flag if STATUS_NOT_CONFIGURED > N
        # "max_not_configured": 0,
        "severity": "Medium",
    },
    "EDRDisabledEndpoints": {
        "min_rows": 1,  # trigger if more than this many endpoints have EDR disabled
        "severity": "Medium",
    },
    # Ingestion / Integration / Configuration
    "CIEIngestedDomains": {
        # TODO: define threshold — e.g. flag if no domains ingested
        # "min_domains": 1,
        "severity": "Medium",
    },
    "CIENonReportingDomains": {
        # TODO: define threshold — e.g. flag if daysNoUpdate > N
        # "max_days_no_update": 30,
        "severity": "High",
    },
    "HealthIssues": {
        # TODO: define threshold — e.g. flag if total issue count > N
        # "max_total_issues": 10,
        "severity": "Medium",
    },
    "PlaybookFailingTasks": {
        # TODO: define threshold — e.g. flag if any task has > N failures
        # "max_failing_tasks": 5,
        "severity": "High",
    },
    "SourcesFeedingAuthPreset": {
        # TODO: define threshold — e.g. flag if fewer than N sources feeding
        # "min_sources": 1,
        "severity": "Medium",
    },
    "SourcesFeedingNetworkPreset": {
        # TODO: define threshold — e.g. flag if fewer than N sources feeding
        # "min_sources": 1,
        "severity": "Medium",
    },
    "SourcesFeedingSaaSAudit": {
        # TODO: define threshold — e.g. flag if no sources feeding
        # "min_sources": 1,
        "severity": "Low",
    },
    # Issues / Cases
    "CorrelationRulesWithoutAutomation": {
        # TODO: define threshold — e.g. flag if any rule has count > N
        # "max_count": 0,
        "severity": "Medium",
    },
    "NoisyIssueCategories": {
        # TODO: define threshold — e.g. flag if any category has Alerts > N
        # "max_alerts_per_category": 100,
        "severity": "Low",
    },
    "NonPreventedIssues": {
        # TODO: define threshold — e.g. flag if any non-prevented issue exists
        # "min_rows": 1,
        "severity": "High",
    },
}


# ---------------------------------------------------------------------------
# Key normalisation
# ---------------------------------------------------------------------------

# Strips leading "Health Check - <Dashboard>[-<variant>] - " prefix.
# Handles both "Health Check - Agent and Asset - " and
# "Health Check - Agent and Asset-HC-test - " variants.
_PREFIX_RE = re.compile(
    r"^Health\s+Check\s*-\s*[^-]+(?:-[^-]+)?\s*-\s*",
    re.IGNORECASE,
)

# Strips trailing " xql_<digits>" suffix.
_XQL_SUFFIX_RE = re.compile(r"\s*xql_\d+$", re.IGNORECASE)

# Also strip trailing time-window tags like " - 7d", " - 30d", " - 3d"
_TIME_WINDOW_RE = re.compile(r"\s*-\s*\d+d$", re.IGNORECASE)


def _clean_key(raw_key: str) -> str:
    """Strip dashboard prefix, XQL-ID suffix, and time-window suffix."""
    key = _PREFIX_RE.sub("", raw_key)
    key = _XQL_SUFFIX_RE.sub("", key)
    key = _TIME_WINDOW_RE.sub("", key)
    return key.strip()


# Maps a *substring* (case-insensitive) found in the cleaned key to the
# canonical widget name used in THRESHOLDS and WIDGET_HANDLERS.
# Order matters: more specific substrings should come first.
WIDGET_KEY_MAP: list[tuple[str, str]] = [
    # Agent & Asset
    ("Agent Policy Assignment", "AgentPolicyAssignment"),
    ("Agent Scan Status", "AgentScanStatus"),
    ("Auto Agent Upgrade Status", "AutoAgentUpgradeStatus"),
    ("EDR Disabled Endpoints", "EDRDisabledEndpoints"),
    # Ingestion / Integration / Configuration
    ("CIE - Ingested Domains", "CIEIngestedDomains"),
    ("CIE Non Reporting Domains", "CIENonReportingDomains"),
    ("Health Issues", "HealthIssues"),
    ("Playbook Failing Tasks", "PlaybookFailingTasks"),
    ("Sources Feeding Authentication", "SourcesFeedingAuthPreset"),
    ("Sources Feeding Network", "SourcesFeedingNetworkPreset"),
    ("Sources Feeding SaaS", "SourcesFeedingSaaSAudit"),
    # Issues / Cases
    ("Correlation Rules Without Automation", "CorrelationRulesWithoutAutomation"),
    ("Noisy Issue Categories", "NoisyIssueCategories"),
    ("Non-Prevented Issues", "NonPreventedIssues"),
]


def classify_key(raw_key: str) -> str | None:
    """Return the canonical widget name for *raw_key*, or None if unknown."""
    cleaned = _clean_key(raw_key)
    for substring, canonical in WIDGET_KEY_MAP:
        if substring.lower() in cleaned.lower():
            return canonical
    return None


# ---------------------------------------------------------------------------
# Handler functions  (one per widget)
# ---------------------------------------------------------------------------
# Signature: handler(rows: list[dict], cfg: dict) -> list[ActionItem]
#
# Each handler:
#   • Inspects the raw rows from CollectResults.
#   • Compares values against cfg (from THRESHOLDS).
#   • Returns a (possibly empty) list of ActionItem dicts.
#
# TODO: implement the threshold logic inside each handler once the threshold
#       values and action item text have been agreed with the user.
# ---------------------------------------------------------------------------


def handle_agent_policy_assignment(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"assigned_prevention_policy": str, "policy_count": int}

    TODO: decide what constitutes a problem here and fill in:
      - threshold condition (e.g. too many policies, policy with 0 endpoints)
      - category / description / resolution text
    """
    action_items: list[ActionItem] = []
    # Example skeleton (disabled until threshold is defined):
    # max_policies = cfg.get("max_policies")
    # if max_policies is not None and len(rows) > max_policies:
    #     action_items.append(make_action_item(
    #         category="Agent & Asset",
    #         description=f"Too many prevention policies assigned ({len(rows)} > {max_policies})",
    #         resolution="TODO",
    #         severity=cfg.get("severity", "Low"),
    #     ))
    return action_items


def handle_agent_scan_status(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"scan_status": str, "scancount": int}

    TODO: decide threshold (e.g. IN_PROGRESS count > N means scans are stuck).
    """
    action_items: list[ActionItem] = []
    # Example skeleton:
    # max_in_progress = cfg.get("max_in_progress")
    # in_progress = sum(r.get("scancount", 0) for r in rows if r.get("scan_status") == "IN_PROGRESS")
    # if max_in_progress is not None and in_progress > max_in_progress:
    #     action_items.append(make_action_item(
    #         category="Agent & Asset",
    #         description=f"{in_progress} agents stuck in IN_PROGRESS scan state",
    #         resolution="TODO",
    #         severity=cfg.get("severity", "Medium"),
    #     ))
    return action_items


def handle_auto_agent_upgrade_status(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"auto_upgrade_status": str, "upgradestatuscount": int}

    TODO: decide threshold (e.g. STATUS_NOT_CONFIGURED > 0 is a finding).
    """
    action_items: list[ActionItem] = []
    # Example skeleton:
    # max_not_configured = cfg.get("max_not_configured")
    # not_configured = sum(
    #     r.get("upgradestatuscount", 0) for r in rows
    #     if r.get("auto_upgrade_status") == "STATUS_NOT_CONFIGURED"
    # )
    # if max_not_configured is not None and not_configured > max_not_configured:
    #     action_items.append(make_action_item(
    #         category="Agent & Asset",
    #         description=f"{not_configured} agents have auto-upgrade not configured",
    #         resolution="TODO",
    #         severity=cfg.get("severity", "Medium"),
    #     ))
    return action_items


def handle_edr_disabled_endpoints(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"Policy": str, "name": str, "type": str}
    Threshold (from THRESHOLDS["EDRDisabledEndpoints"]):
      min_rows  — trigger if number of affected endpoints exceeds this value
      severity  — severity of the generated action item
    """
    action_items: list[ActionItem] = []
    min_rows = cfg.get("min_rows", 1)
    if len(rows) > min_rows:
        names = ", ".join(r.get("name", "unknown") for r in rows)
        action_items.append(
            make_action_item(
                category="Agent & Asset",
                description=f"EDR is disabled on {len(rows)} endpoints: {names}",
                resolution="Review the prevention policy assigned to these endpoints and enable EDR protection.",
                severity=cfg.get("severity", "Medium"),
            )
        )
    return action_items


def handle_cie_ingested_domains(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"IdentityDomain": str, "generatedTime": int, ...}

    TODO: decide threshold (e.g. no domains ingested = finding).
    """
    action_items: list[ActionItem] = []
    # Example skeleton:
    # min_domains = cfg.get("min_domains", 1)
    # if len(rows) < min_domains:
    #     action_items.append(make_action_item(
    #         category="Ingestion / Integration",
    #         description="No identity domains are being ingested via CIE",
    #         resolution="TODO",
    #         severity=cfg.get("severity", "Medium"),
    #     ))
    return action_items


def handle_cie_non_reporting_domains(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"daysNoUpdate": int, "name": str, ...}

    TODO: decide threshold (e.g. daysNoUpdate > 30 = finding).
    """
    action_items: list[ActionItem] = []
    # Example skeleton:
    # max_days = cfg.get("max_days_no_update")
    # stale = [r for r in rows if r.get("daysNoUpdate", 0) > (max_days or 0)]
    # if max_days is not None and stale:
    #     names = ", ".join(r.get("name", "unknown") for r in stale)
    #     action_items.append(make_action_item(
    #         category="Ingestion / Integration",
    #         description=f"{len(stale)} CIE domain(s) have not reported in >{max_days} days: {names}",
    #         resolution="TODO",
    #         severity=cfg.get("severity", "High"),
    #     ))
    return action_items


def handle_health_issues(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"count": int, "xdm.issue.name": str, "xdm.issue.type": str}

    TODO: decide threshold (e.g. total issue count > N, or any Collection issue).
    """
    action_items: list[ActionItem] = []
    # Example skeleton:
    # max_total = cfg.get("max_total_issues")
    # total = sum(r.get("count", 0) for r in rows)
    # if max_total is not None and total > max_total:
    #     action_items.append(make_action_item(
    #         category="Ingestion / Integration",
    #         description=f"{total} health issues detected in the last 7 days",
    #         resolution="TODO",
    #         severity=cfg.get("severity", "Medium"),
    #     ))
    return action_items


def handle_playbook_failing_tasks(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"task_name": str, "tasks": list[str]}

    TODO: decide threshold (e.g. any task with > N failures = finding).
    """
    action_items: list[ActionItem] = []
    # Example skeleton:
    # max_failures = cfg.get("max_failing_tasks")
    # for row in rows:
    #     task_count = len(row.get("tasks", []))
    #     if max_failures is not None and task_count > max_failures:
    #         action_items.append(make_action_item(
    #             category="Ingestion / Integration",
    #             description=f"Playbook task '{row.get('task_name')}' failed {task_count} times in 30 days",
    #             resolution="TODO",
    #             severity=cfg.get("severity", "High"),
    #         ))
    return action_items


def handle_sources_feeding_auth_preset(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"_product": str, "_vendor": str, "assacioatedproducts": str, ...}

    TODO: decide threshold (e.g. fewer than N distinct sources = finding).
    """
    action_items: list[ActionItem] = []
    # Example skeleton:
    # min_sources = cfg.get("min_sources", 1)
    # if len(rows) < min_sources:
    #     action_items.append(make_action_item(
    #         category="Ingestion / Integration",
    #         description="No sources are feeding the Authentication data preset",
    #         resolution="TODO",
    #         severity=cfg.get("severity", "Medium"),
    #     ))
    return action_items


def handle_sources_feeding_network_preset(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"_product": str, "_vendor": str, "assacioatedproducts": str, ...}

    TODO: decide threshold (e.g. fewer than N distinct sources = finding).
    """
    action_items: list[ActionItem] = []
    # Example skeleton:
    # min_sources = cfg.get("min_sources", 1)
    # if len(rows) < min_sources:
    #     action_items.append(make_action_item(
    #         category="Ingestion / Integration",
    #         description="No sources are feeding the Network data preset",
    #         resolution="TODO",
    #         severity=cfg.get("severity", "Medium"),
    #     ))
    return action_items


def handle_sources_feeding_saas_audit(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"_time": int, "ingestion_time": int, "product": str}

    TODO: decide threshold (e.g. no rows = no SaaS sources feeding = finding).
    """
    action_items: list[ActionItem] = []
    # Example skeleton:
    # min_sources = cfg.get("min_sources", 1)
    # if len(rows) < min_sources:
    #     action_items.append(make_action_item(
    #         category="Ingestion / Integration",
    #         description="No sources are feeding the SaaS Audit dataset",
    #         resolution="TODO",
    #         severity=cfg.get("severity", "Low"),
    #     ))
    return action_items


def handle_correlation_rules_without_automation(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"count": int, "xdm.issue.name": str}

    TODO: decide threshold (e.g. any rule with count > N = finding).
    """
    action_items: list[ActionItem] = []
    # Example skeleton:
    # max_count = cfg.get("max_count")
    # noisy = [r for r in rows if r.get("count", 0) > (max_count or 0)]
    # if max_count is not None and noisy:
    #     action_items.append(make_action_item(
    #         category="Issues / Cases",
    #         description=f"{len(noisy)} correlation rule(s) fired without automation",
    #         resolution="TODO",
    #         severity=cfg.get("severity", "Medium"),
    #     ))
    return action_items


def handle_noisy_issue_categories(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"Alerts": int, "xdm.issue.detection.method": str}

    TODO: decide threshold (e.g. any category with Alerts > N = finding).
    """
    action_items: list[ActionItem] = []
    # Example skeleton:
    # max_alerts = cfg.get("max_alerts_per_category")
    # noisy = [r for r in rows if r.get("Alerts", 0) > (max_alerts or 0)]
    # if max_alerts is not None and noisy:
    #     for r in noisy:
    #         action_items.append(make_action_item(
    #             category="Issues / Cases",
    #             description=f"Detection method '{r['xdm.issue.detection.method']}' generated {r['Alerts']} alerts",
    #             resolution="TODO",
    #             severity=cfg.get("severity", "Low"),
    #         ))
    return action_items


def handle_non_prevented_issues(rows: list[dict], cfg: dict) -> list[ActionItem]:
    """
    Raw row shape: {"alert_name": str, "assigned_prevention_policy": str, "events": int}

    TODO: decide threshold (e.g. any row = finding, or only if events > N).
    """
    action_items: list[ActionItem] = []
    # Example skeleton:
    # min_rows = cfg.get("min_rows", 1)
    # if len(rows) >= min_rows:
    #     action_items.append(make_action_item(
    #         category="Issues / Cases",
    #         description=f"{len(rows)} non-prevented issue(s) detected",
    #         resolution="TODO",
    #         severity=cfg.get("severity", "High"),
    #     ))
    return action_items


# ---------------------------------------------------------------------------
# Widget handler registry
# ---------------------------------------------------------------------------
# Maps canonical widget name → handler function.
# Must stay in sync with THRESHOLDS and WIDGET_KEY_MAP.
# ---------------------------------------------------------------------------

WIDGET_HANDLERS: dict = {
    # Agent & Asset
    "AgentPolicyAssignment": handle_agent_policy_assignment,
    "AgentScanStatus": handle_agent_scan_status,
    "AutoAgentUpgradeStatus": handle_auto_agent_upgrade_status,
    "EDRDisabledEndpoints": handle_edr_disabled_endpoints,
    # Ingestion / Integration / Configuration
    "CIEIngestedDomains": handle_cie_ingested_domains,
    "CIENonReportingDomains": handle_cie_non_reporting_domains,
    "HealthIssues": handle_health_issues,
    "PlaybookFailingTasks": handle_playbook_failing_tasks,
    "SourcesFeedingAuthPreset": handle_sources_feeding_auth_preset,
    "SourcesFeedingNetworkPreset": handle_sources_feeding_network_preset,
    "SourcesFeedingSaaSAudit": handle_sources_feeding_saas_audit,
    # Issues / Cases
    "CorrelationRulesWithoutAutomation": handle_correlation_rules_without_automation,
    "NoisyIssueCategories": handle_noisy_issue_categories,
    "NonPreventedIssues": handle_non_prevented_issues,
}


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_context_data() -> dict[str, Any]:
    """Load HealthCheck data from the live incident context."""
    ctx = demisto.context()
    health_check = ctx.get("HealthCheck", {})
    if not health_check:
        raise ValueError("HealthCheck key not found in incident context")
    return health_check


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------


def parse_collect_results(collect_results: dict) -> list[ActionItem]:
    """Iterate over every widget, call its handler, return all action items.
    the accumulated list of ActionItem dicts.
    """
    action_items: list[ActionItem] = []
    seen_canonical: set[str] = set()

    for raw_key, rows in collect_results.items():
        canonical = classify_key(raw_key)
        if canonical is None:
            demisto.debug(f"HealthCheckParseResults: unrecognised widget key '{raw_key}' — skipping")
            continue

        # De-duplicate: the same widget may appear under multiple raw keys
        # (e.g. with and without the dashboard prefix).  Process only once.
        if canonical in seen_canonical:
            demisto.debug(f"HealthCheckParseResults: duplicate canonical '{canonical}' from '{raw_key}' — skipping")
            continue
        seen_canonical.add(canonical)

        handler = WIDGET_HANDLERS.get(canonical)
        if handler is None:
            demisto.debug(f"HealthCheckParseResults: no handler registered for '{canonical}' — skipping")
            continue

        cfg = THRESHOLDS.get(canonical, {})

        if not isinstance(rows, list):
            demisto.debug(f"HealthCheckParseResults: rows for '{canonical}' is not a list — skipping")
            continue

        try:
            items = handler(rows, cfg)

            action_items.extend(items)
        except Exception as exc:  # noqa: BLE001
            demisto.error(f"HealthCheckParseResults: handler for '{canonical}' raised {exc}")

    return action_items


def main() -> None:
    try:
        raw_data = load_context_data()

        collect_results: dict[str, list[dict]] = raw_data.get("CollectResults") or {}

        if not collect_results:
            return_warning("HealthCheck.CollectResults is empty — nothing to parse")
            return

        action_items = parse_collect_results(collect_results)

        return_results(
            CommandResults(
                outputs_prefix="HealthCheck",
                outputs_key_field="",
                outputs={"ActionableItems": action_items},
                readable_output=tableToMarkdown(
                    "HealthCheck Actionable Items",
                    action_items,
                    headers=["category", "severity", "description", "resolution"],
                )
                if action_items
                else "No actionable items generated.",
            )
        )

    except Exception as exc:
        return_error(f"HealthCheckParseResults failed: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
