import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


ALERT_BODY: dict = {
    "request_data": {
        "alert": {
            "vendor": "PANW",
            "product": "XSIAM Manual",
            "severity": "High",
            "category": "Healthcheck Report",
            "mitre_defs": {},
            "description": "New Healthcheck data collection alert",
            "alert_name": "Healthcheck Report and BPA diagnostics",
            "alert_type": "Automation",
            "alert_domain": "DOMAIN_HEALTH",
        }
    }
}


def create_healthcheck_alert() -> dict:
    """Create a HealthCheck alert via the XSIAM local API.

    Returns:
        dict: The API response reply containing the created alert details.

    Raises:
        ValueError: If the API call fails or returns an unexpected structure.
    """
    demisto.debug("HealthCheckStart: creating healthcheck alert via public_api/v1/alerts/create_alert")

    result = demisto.executeCommand(
        "core-api-post",
        {
            "uri": "/public_api/v1/alerts/create_alert",
            "body": json.dumps(ALERT_BODY),
        },
    )

    if is_error(result):
        raise ValueError(f"Failed to create alert: {get_error(result)}")

    try:
        response = result[0]["Contents"]["response"]
        reply = response.get("reply", response)
        demisto.debug(f"HealthCheckStart: alert created successfully: {reply}")
        return reply
    except (KeyError, IndexError, TypeError) as e:
        raise ValueError(f"Unexpected response structure from create_alert: {e}") from e


def main() -> None:
    try:
        reply = create_healthcheck_alert()

        alert_id = reply.get("alert_id") if isinstance(reply, dict) else None
        server_url = demisto.demistoUrls().get("server", "")

        if alert_id:
            alert_url = f"{server_url}/alerts/{alert_id}"
            message = f"HealthCheck alert created successfully.\n\n[Open Alert #{alert_id}]({alert_url})"
        else:
            message = "HealthCheck alert created successfully."

        demisto.results(
            {
                "Type": entryTypes["note"],
                "ContentsFormat": formats["markdown"],
                "Contents": message,
            }
        )

    except Exception as e:
        return_error(f"HealthCheckStart failed: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
