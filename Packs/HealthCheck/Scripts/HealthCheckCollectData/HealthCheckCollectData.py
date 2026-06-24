import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
from typing import Any

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------


def api_post(uri: str, body: dict) -> Any:
    """Call core-api-post and return the response payload, raising on error."""
    result = demisto.executeCommand(
        "core-api-post",
        {"uri": uri, "body": json.dumps(body)},
    )
    if is_error(result):
        raise ValueError(f"API call to {uri} failed: {get_error(result)}")
    return result[0]["Contents"]["response"]["reply"]


# ---------------------------------------------------------------------------
# Agents collectors
# ---------------------------------------------------------------------------


def get_endpoint_total_count(filters: list) -> int:
    """
    Shared helper: call /public_api/v1/endpoints/get_endpoints with the given
    filters list and return total_count from the reply.

    Args:
        filters: list of filter dicts, e.g.
            [{"field": "endpoint_status", "operator": "in", "value": ["connected"]}]
    """
    body = {
        "request_data": {
            "search_from": 0,
            "search_to": 1,
            "filters": filters,
        }
    }
    reply = api_post("/public_api/v1/endpoints/get_endpoint", body)
    return reply.get("total_count", 0)


# All valid endpoint status values
ENDPOINT_STATUSES = ["connected", "lost", "disconnected", "uninstalled"]


def collect_agent_status_breakdown(_unused: Any) -> dict:
    """
    Widget: Agent Status Breakdown
    Calls get_endpoint_total_count once per status value.
    Returns: {"connected": N, "lost": N, "disconnected": N, "uninstalled": N}
    """
    result: dict = {}
    for status in ENDPOINT_STATUSES:
        total = get_endpoint_total_count([{"field": "endpoint_status", "operator": "in", "value": [status]}])
        demisto.debug(f"[HealthCheckCollectData] status={status} total_count={total}")
        result[status] = total
    return result


def collect_agent_eol_versions(_unused: Any) -> dict:
    """
    Widget: Agent End-of-Life Versions
    Calls get_endpoint_total_count filtered by endpoint_version_is_outdated=True.
    Returns: {"total_eol_endpoints": N}
    """
    total = get_endpoint_total_count([{"field": "endpoint_version_is_outdated", "operator": "in", "value": [True]}])
    demisto.debug(f"[HealthCheckCollectData] EOL endpoints total_count={total}")
    return {"total_eol_endpoints": total}


# ---------------------------------------------------------------------------
# Collector registry
# ---------------------------------------------------------------------------
# Maps argument name → list of (widget_name, collector_function) tuples.
# Each collector is self-contained and fetches its own data.
# ---------------------------------------------------------------------------

COLLECTORS: dict[str, list[tuple[str, Any]]] = {
    "Agents": [
        ("Agent Status Breakdown", collect_agent_status_breakdown),
        ("Agent End-of-Life Versions", collect_agent_eol_versions),
    ],
    # "Cases": [
    #     ("My Cases Widget", collect_my_cases_widget),
    # ],
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    args = demisto.args()
    data = args.get("data", "")

    if not data:
        return_error("Missing required argument: data. Valid options: Agents, Cases")
        return

    collectors = COLLECTORS.get(data)
    if collectors is None:
        return_error(f"Unknown data value '{data}'. Valid options: {', '.join(COLLECTORS.keys())}")
        return

    demisto.debug(f"[HealthCheckCollectData] collecting data for: {data}")
    outputs: list[CommandResults] = []

    for widget_name, collector_fn in collectors:
        try:
            result = collector_fn(None)
            demisto.debug(f"[HealthCheckCollectData] {widget_name}: collected")
            outputs.append(
                CommandResults(
                    outputs_prefix="HealthCheck.CollectResults",
                    outputs={widget_name: result},
                    readable_output=tableToMarkdown(
                        widget_name,
                        [result] if isinstance(result, dict) else result,
                        headers=list(result.keys()) if isinstance(result, dict) else (list(result[0].keys()) if result else []),
                    )
                    if result
                    else f"**{widget_name}**: no data",
                )
            )
        except Exception as exc:
            demisto.error(f"[HealthCheckCollectData] collector '{widget_name}' failed: {exc}")

    if not outputs:
        return_warning("HealthCheckCollectData: no data collected.")
        return

    return_results(outputs)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
