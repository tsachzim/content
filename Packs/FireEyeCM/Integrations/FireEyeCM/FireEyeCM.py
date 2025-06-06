import urllib3
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
INTEGRATION_NAME = "FireEye Central Management"
INTEGRATION_COMMAND_NAME = "fireeye-cm"
INTEGRATION_CONTEXT_NAME = "FireEyeCM"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR


class Client:
    """
    The integration's client
    """

    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool):
        self.fe_client: FireEyeClient = FireEyeClient(
            base_url=base_url, username=username, password=password, verify=verify, proxy=proxy
        )


@logger
def run_test_module(client: Client) -> str:
    client.fe_client.get_alerts_request({"info_level": "concise"})
    return "ok"


@logger
def get_alerts(client: Client, args: Dict[str, Any]) -> CommandResults:
    def parse_request_params(args: Dict[str, Any]) -> Dict:
        alert_id = args.get("alert_id", "")
        start_time = args.get("start_time", "")
        if start_time:
            start_time = to_fe_datetime_converter(start_time)
        end_time = args.get("end_time")
        if end_time:
            end_time = to_fe_datetime_converter(end_time)
        duration = args.get("duration")
        callback_domain = args.get("callback_domain", "")
        dst_ip = args.get("dst_ip", "")
        src_ip = args.get("src_ip", "")
        file_name = args.get("file_name", "")
        file_type = args.get("file_type", "")
        malware_name = args.get("malware_name", "")
        malware_type = args.get("malware_type", "")
        recipient_email = args.get("recipient_email", "")
        sender_email = args.get("sender_email", "")
        url_ = args.get("url", "")

        request_params = {"info_level": args.get("info_level", "concise")}
        if start_time:
            request_params["start_time"] = start_time
        if end_time:
            request_params["end_time"] = end_time
        if duration:
            request_params["duration"] = duration
        if alert_id:
            request_params["alert_id"] = alert_id
        if callback_domain:
            request_params["callback_domain"] = callback_domain
        if dst_ip:
            request_params["dst_ip"] = dst_ip
        if src_ip:
            request_params["src_ip"] = src_ip
        if file_name:
            request_params["file_name"] = file_name
        if file_type:
            request_params["file_type"] = file_type
        if malware_name:
            request_params["malware_name"] = malware_name
        if malware_type:
            request_params["malware_type"] = malware_type
        if recipient_email:
            request_params["recipient_email"] = recipient_email
        if sender_email:
            request_params["sender_email"] = sender_email
        if url_:
            request_params["url"] = url_
        return request_params

    request_params = parse_request_params(args)
    limit = int(args.get("limit", "20"))
    timeout = int(args.get("timeout", "120"))

    raw_response = client.fe_client.get_alerts_request(request_params, timeout=timeout)

    alerts = raw_response.get("alert")
    if not alerts:
        md_ = f"No alerts with the given arguments were found.\n Arguments {request_params!s}"
    else:
        alerts = alerts[:limit]
        headers = ["id", "occurred", "product", "name", "malicious", "severity", "alertUrl"]
        md_ = tableToMarkdown(name=f"{INTEGRATION_NAME} Alerts:", t=alerts, headers=headers, removeNull=True)

    return CommandResults(
        readable_output=md_,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Alerts",
        outputs_key_field="uuid",
        outputs=alerts,
        raw_response=raw_response,
    )


@logger
def get_alert_details(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    alert_ids = argToList(args.get("alert_id"))
    timeout = int(args.get("timeout", "120"))

    command_results: List[CommandResults] = []

    headers = ["id", "occurred", "product", "name", "malicious", "action", "src", "dst", "severity", "alertUrl"]

    for alert_id in alert_ids:
        raw_response = client.fe_client.get_alert_details_request(alert_id, timeout)

        alert_details = raw_response.get("alert")
        if not alert_details:
            md_ = f"Alert {alert_id} was not found."
        else:
            md_ = tableToMarkdown(name=f"{INTEGRATION_NAME} Alerts:", t=alert_details, headers=headers, removeNull=True)

        command_results.append(
            CommandResults(
                readable_output=md_,
                outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Alerts",
                outputs_key_field="uuid",
                outputs=alert_details,
                raw_response=raw_response,
            )
        )

    return command_results


@logger
def alert_acknowledge(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    uuids = argToList(args.get("uuid"))
    command_results: List[CommandResults] = []

    for uuid in uuids:
        try:
            client.fe_client.alert_acknowledge_request(uuid)
            md_ = f"Alert {uuid} was acknowledged successfully."
        except Exception as err:
            if "Error in API call [404]" in str(err):
                md_ = f"Alert {uuid} was not found or cannot update. It may have been acknowledged in the past."
            else:
                raise

        command_results.append(CommandResults(readable_output=md_))

    return command_results


@logger
def get_artifacts_by_uuid(client: Client, args: Dict[str, Any]):
    uuids = argToList(args.get("uuid"))
    timeout = int(args.get("timeout", "120"))

    for uuid in uuids:
        artifact = client.fe_client.get_artifacts_by_uuid_request(uuid, timeout)
        demisto.results(fileResult(f"artifacts_{uuid}.zip", data=artifact, file_type=EntryType.ENTRY_INFO_FILE))


@logger
def get_artifacts_metadata_by_uuid(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    uuids: List[str] = argToList(str(args.get("uuid")))
    command_results: List[CommandResults] = []

    for uuid in uuids:
        raw_response = client.fe_client.get_artifacts_metadata_by_uuid_request(uuid)

        outputs = raw_response
        outputs["uuid"] = uuid  # type: ignore
        md_ = tableToMarkdown(
            name=f"{INTEGRATION_NAME} {uuid} Artifact metadata:", t=raw_response.get("artifactsInfoList"), removeNull=True
        )

        command_results.append(
            CommandResults(
                readable_output=md_,
                outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Alerts",
                outputs_key_field="uuid",
                outputs=outputs,
                raw_response=raw_response,
            )
        )

    return command_results


@logger
def get_events(client: Client, args: Dict[str, Any]) -> CommandResults:
    duration = args.get("duration", "12_hours")
    end_time = to_fe_datetime_converter(args.get("end_time", "now"))
    mvx_correlated_only = argToBoolean(args.get("mvx_correlated_only", "false"))
    limit = int(args.get("limit", "20"))

    raw_response = client.fe_client.get_events_request(duration, end_time, mvx_correlated_only)

    events = raw_response.get("events")
    if not events:
        md_ = "No events in the given timeframe were found."
    else:
        events = events[:limit]
        headers = ["occurred", "ruleName", "severity", "malicious", "cveId", "eventId", "srcIp", "dstIp"]
        md_ = tableToMarkdown(name=f"{INTEGRATION_NAME} Events:", t=events, headers=headers, removeNull=True)

    return CommandResults(
        readable_output=md_,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Events",
        outputs_key_field="eventId",
        outputs=events,
        raw_response=raw_response,
    )


@logger
def get_quarantined_emails(client: Client, args: Dict[str, Any]) -> CommandResults:
    start_time = to_fe_datetime_converter(args.get("start_time", "1 day"))
    end_time = to_fe_datetime_converter(args.get("end_time", "now"))
    from_ = args.get("from", "")
    subject = args.get("subject", "")
    appliance_id = args.get("appliance_id", "")
    limit = args.get("limit", "10000")

    raw_response = client.fe_client.get_quarantined_emails_request(start_time, end_time, from_, subject, appliance_id, limit)
    if not raw_response:
        md_ = "No emails with the given query arguments were found."
    else:
        headers = ["email_uuid", "from", "subject", "message_id", "completed_at"]
        md_ = tableToMarkdown(name=f"{INTEGRATION_NAME} Quarantined emails:", t=raw_response, headers=headers, removeNull=True)

    return CommandResults(
        readable_output=md_,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.QuarantinedEmail",
        outputs_key_field="email_uuid",
        outputs=raw_response,
        raw_response=raw_response,
    )


@logger
def release_quarantined_emails(client: Client, args: Dict[str, Any]) -> CommandResults:
    sensor_name = args.get("sensor_name", "")
    queue_ids = argToList(args.get("queue_ids", ""))

    raw_response = client.fe_client.release_quarantined_emails_request(queue_ids, sensor_name)

    if raw_response.text:  # returns 200 either way. if operation is successful than resp is empty
        raise DemistoException(raw_response.json())
    else:
        md_ = f"{INTEGRATION_NAME} released emails successfully."
    return CommandResults(readable_output=md_, raw_response="")


@logger
def delete_quarantined_emails(client: Client, args: Dict[str, Any]) -> CommandResults:
    sensor_name = args.get("sensor_name", "")
    queue_ids = argToList(args.get("queue_ids", ""))

    raw_response = client.fe_client.delete_quarantined_emails_request(queue_ids, sensor_name)
    if raw_response.text:  # returns 200 either way. if operation is successful than resp is empty
        raise DemistoException(raw_response.json())
    else:
        md_ = f"{INTEGRATION_NAME} deleted emails successfully."

    return CommandResults(readable_output=md_, raw_response="")


@logger
def download_quarantined_emails(client: Client, args: Dict[str, Any]):
    sensor_name = args.get("sensor_name", "")
    queue_id = args.get("queue_id", "")
    timeout = int(args.get("timeout", "120"))

    raw_response = client.fe_client.download_quarantined_emails_request(queue_id, timeout, sensor_name)

    demisto.results(fileResult(f"quarantined_email_{queue_id}.eml", data=raw_response, file_type=EntryType.FILE))


@logger
def get_reports(client: Client, args: Dict[str, Any]):
    report_type = args.get("report_type", "")
    start_time = to_fe_datetime_converter(args.get("start_time", "1 week"))
    end_time = to_fe_datetime_converter(args.get("end_time", "now"))
    limit = args.get("limit", "100")
    interface = args.get("interface", "")
    alert_id = args.get("alert_id", "")
    infection_id = args.get("infection_id", "")
    infection_type = args.get("infection_type", "")
    timeout = int(args.get("timeout", "120"))

    if report_type == "alertDetailsReport":  # validate arguments
        # can use either alert_id, or infection_type and infection_id
        err_str = "The alertDetailsReport can be retrieved using alert_id argument alone, or by infection_type and infection_id"
        if alert_id:
            if infection_id or infection_type:
                raise DemistoException(err_str)
        else:
            if not infection_id and not infection_type:
                raise DemistoException(err_str)

    try:
        raw_response = client.fe_client.get_reports_request(
            report_type, start_time, end_time, limit, interface, alert_id, infection_type, infection_id, timeout
        )
        csv_reports = {"empsEmailAVReport", "empsEmailHourlyStat", "mpsCallBackServer", "mpsInfectedHostsTrend", "mpsWebAVReport"}
        prefix = "csv" if report_type in csv_reports else "pdf"
        demisto.results(
            fileResult(
                f"report_{report_type}_{datetime.now().timestamp()}.{prefix}",
                data=raw_response,
                file_type=EntryType.ENTRY_INFO_FILE,
            )
        )
    except Exception as err:
        if "WSAPI_REPORT_ALERT_NOT_FOUND" in str(err):
            return CommandResults(readable_output=f"Report {report_type} was not found with the given arguments.")
        else:
            raise


@logger
def fetch_incidents(
    client: Client, last_run: dict, first_fetch: str, max_fetch: int = 50, info_level: str = "concise"
) -> tuple[dict, list]:
    if not last_run:  # if first time fetching
        next_run = {"time": to_fe_datetime_converter(first_fetch), "last_alert_ids": []}
    else:
        next_run = last_run

    demisto.info(f'{INTEGRATION_NAME} executing fetch with: {next_run.get("time")!s}')
    raw_response = client.fe_client.get_alerts_request(
        request_params={
            "start_time": to_fe_datetime_converter(next_run["time"]),  # type: ignore
            "info_level": info_level,
            "duration": "48_hours",
        }
    )
    all_alerts = raw_response.get("alert")

    ten_minutes = dateparser.parse("10 minutes")
    assert ten_minutes is not None
    if not all_alerts:
        demisto.info(f"{INTEGRATION_NAME} no alerts were fetched from FireEye server at: {next_run!s}")
        # as no alerts occurred in the window of 48 hours from the given start time, update last_run window to the next
        # 48 hours. If it is later than now -10 minutes take the latter (to avoid missing events).
        next_run_time_date = dateparser.parse(str(next_run["time"]))
        assert next_run_time_date is not None
        two_days_from_last_search = next_run_time_date + timedelta(hours=48)
        now_minus_ten_minutes = ten_minutes.astimezone(two_days_from_last_search.tzinfo)
        next_search = min(two_days_from_last_search, now_minus_ten_minutes)
        next_run = {"time": next_search.isoformat(), "last_alert_ids": []}
        demisto.info(f"{INTEGRATION_NAME} setting next run to: {next_run!s}")
        return next_run, []

    alerts = all_alerts[:max_fetch]
    last_alert_ids = last_run.get("last_alert_ids", [])
    incidents = []

    for alert in alerts:
        alert_id = str(alert.get("id"))
        if alert_id not in last_alert_ids:  # check that event was not fetched in the last fetch
            occurred_date = dateparser.parse(alert.get("occurred"))
            assert occurred_date is not None, f"could not parse {alert.get('occurred')}"
            incident = {
                "name": f"{INTEGRATION_NAME} Alert: {alert_id}",
                "occurred": occurred_date.strftime(DATE_FORMAT),
                "severity": alert_severity_to_dbot_score(alert.get("severity")),
                "rawJSON": json.dumps(alert),
            }
            incidents.append(incident)
            last_alert_ids.append(alert_id)

    if not incidents:
        demisto.info(f"{INTEGRATION_NAME} no new alerts were collected at: {next_run!s}.")
        # As no incidents were collected, we know that all the fetched alerts for 48 hours starting in the 'start_time'
        # already exists in our system, thus update last_run time to look for the next 48 hours. If it is later than
        # now -10 minutes take the latter (to avoid missing events)
        parsed_date = dateparser.parse(alerts[-1].get("occurred"))
        assert parsed_date is not None, f"could not parse {alerts[-1].get('occurred')}"
        two_days_from_last_incident = parsed_date + timedelta(hours=48)
        now_minus_ten_minutes = ten_minutes.astimezone(two_days_from_last_incident.tzinfo)
        next_search = min(two_days_from_last_incident, now_minus_ten_minutes)
        next_run["time"] = next_search.isoformat()
        demisto.info(f'{INTEGRATION_NAME} Setting next_run to: {next_run["time"]}')
        return next_run, []

    # as alerts occurred till now, update last_run time accordingly to the that of latest fetched alert
    next_run = {
        "time": alerts[-1].get("occurred"),
        "last_alert_ids": last_alert_ids,  # save the alert IDs from the last fetch
    }
    demisto.info(f"{INTEGRATION_NAME} Fetched {len(incidents)}. last fetch at: {next_run!s}")
    return next_run, incidents


def main() -> None:
    params = demisto.params()
    username = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    # there is also a v1.2.0 which holds different paths and params, we support only the newest API version
    base_url = urljoin(params.get("url"), "/wsapis/v2.0.0/")
    verify = not argToBoolean(params.get("insecure", "false"))
    proxy = argToBoolean(params.get("proxy"))

    # fetch params
    max_fetch = int(params.get("max_fetch", "50"))
    first_fetch = params.get("first_fetch", "3 days").strip()
    info_level = params.get("info_level") or "concise"

    command = demisto.command()
    args = demisto.args()
    LOG(f"Command being called is {command}")
    try:
        client = Client(base_url=base_url, username=username, password=password, verify=verify, proxy=proxy)
        commands = {
            f"{INTEGRATION_COMMAND_NAME}-get-alerts": get_alerts,
            f"{INTEGRATION_COMMAND_NAME}-get-alert-details": get_alert_details,
            f"{INTEGRATION_COMMAND_NAME}-alert-acknowledge": alert_acknowledge,
            f"{INTEGRATION_COMMAND_NAME}-get-artifacts-by-uuid": get_artifacts_by_uuid,
            f"{INTEGRATION_COMMAND_NAME}-get-artifacts-metadata-by-uuid": get_artifacts_metadata_by_uuid,
            f"{INTEGRATION_COMMAND_NAME}-get-events": get_events,
            f"{INTEGRATION_COMMAND_NAME}-get-quarantined-emails": get_quarantined_emails,
            f"{INTEGRATION_COMMAND_NAME}-release-quarantined-emails": release_quarantined_emails,
            f"{INTEGRATION_COMMAND_NAME}-delete-quarantined-emails": delete_quarantined_emails,
            f"{INTEGRATION_COMMAND_NAME}-download-quarantined-emails": download_quarantined_emails,
            f"{INTEGRATION_COMMAND_NAME}-get-reports": get_reports,
        }
        if command == "test-module":
            return_results(run_test_module(client))
        elif command == "fetch-incidents":
            next_run, incidents = fetch_incidents(
                client=client, last_run=demisto.getLastRun(), first_fetch=first_fetch, max_fetch=max_fetch, info_level=info_level
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == f"{INTEGRATION_COMMAND_NAME}-get-artifacts-by-uuid":
            get_artifacts_by_uuid(client, args)
        elif command == f"{INTEGRATION_COMMAND_NAME}-get-reports":
            get_reports(client, args)
        elif command == f"{INTEGRATION_COMMAND_NAME}-download-quarantined-emails":
            download_quarantined_emails(client, args)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(str(err), err)


from FireEyeApiModule import *  # noqa: E402

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
