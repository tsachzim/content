import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import pandas as pd
import time
import io


def execute_xql_query(query, timeframe_ms=7776000000, limit=100000, max_polls=30):
    """Execute XQL query via XSIAM API and return results, handling stream if needed."""

    # Step 1: Start query
    start_body = {
        "request_data": {
            "query": query,
            "timeframe": {"relativeTime": timeframe_ms},
        }
    }

    result = demisto.executeCommand(
        "core-api-post",
        {"uri": "/public_api/v1/xql/start_xql_query", "body": json.dumps(start_body)},
    )

    if is_error(result):
        raise ValueError(f"Failed to start query: {get_error(result)}")

    execution_id = result[0]["Contents"]["response"]["reply"]
    demisto.debug(f"Query started: {execution_id}")

    # Step 2: Poll for results
    poll_body = {
        "request_data": {
            "query_id": execution_id,
            "pending_flag": True,
            "limit": limit,
            "format": "json",
        }
    }

    for _attempt in range(max_polls):
        result = demisto.executeCommand(
            "core-api-post",
            {
                "uri": "/public_api/v1/xql/get_query_results",
                "body": json.dumps(poll_body),
            },
        )

        if is_error(result):
            raise ValueError(f"Failed to get results: {get_error(result)}")

        reply = result[0]["Contents"]["response"]["reply"]
        if reply["status"] == "SUCCESS":
            # Check if stream_id is present (large result set)
            if "stream_id" in reply["results"]:
                stream_id = reply["results"]["stream_id"]
                demisto.debug(f"Stream ID received: {stream_id}, fetching streamed results")
                return get_streamed_results(stream_id)
            else:
                # Regular response with data
                return reply["results"]["data"]
        elif reply["status"] == "FAILED":
            raise ValueError(f"Query failed: {reply.get('error')}")

        time.sleep(3)

    raise TimeoutError("Query timeout")


def get_streamed_results(stream_id):
    """Fetch large result sets using stream_id."""
    stream_body = {"request_data": {"stream_id": stream_id, "is_gzip_compressed": True}}

    result = demisto.executeCommand(
        "core-api-post",
        {
            "uri": "/public_api/v1/xql/get_query_results_stream",
            "body": json.dumps(stream_body),
        },
    )

    if is_error(result):
        raise ValueError(f"Failed to get streamed results: {get_error(result)}")

    reply = result[0]["Contents"]["response"]

    if "data" in reply["results"]:
        return reply["results"]["data"]

    return reply["results"].get("data", [])


def query_agent_upgrade_failures():
    """
    Query agent upgrade failures from agent_auditing dataset.

    XQL performs all filtering, extraction, aggregation, and sorting.

    Returns:
        list[dict]: Array of {hostname, fail_reason, total}
    """
    query = """
    config timeframe = 90d case_sensitive = false
    | dataset = agent_auditing
    | filter agent_auditing_result = ENUM.AGENT_AUDIT_FAIL and agent_auditing_subtype = ENUM.AGENT_AUDIT_UPGRADE
    | alter fail_reason = to_string(regextract(description, "\serror:\s*(.+)"))
    | alter hostname = to_string(regextract(description, "\\bon\s+(\S+)\s+with\s+error:"))
    | comp count() as total by hostname, fail_reason
    | sort desc total
    """

    data = execute_xql_query(query, timeframe_ms=7776000000)
    if not data:
        return []

    # Check if data is a string (JSON Lines format) or list
    if isinstance(data, str):
        df = pd.read_json(io.StringIO(data), lines=True)
        return df.to_dict(orient="records")
    elif isinstance(data, list):
        return data
    else:
        raise ValueError(f"Unexpected data type: {type(data)}")


"""Main function to execute agent upgrade failure analysis."""

# Execute query
results = query_agent_upgrade_failures()
# Output to XSOAR
return_results(
    {
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": {
            "agent_upgrade_failures": results,
            "total_unique_failures": len(results),
        },
        "HumanReadable": tableToMarkdown(
            "Agent Upgrade Failures (Last 90 Days)",
            results,
            headers=["hostname", "fail_reason", "total"],
        ),
    }
)
