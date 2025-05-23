import demistomock as demisto  # noqa: F401   # pragma: no cover
from CommonServerPython import *  # noqa: F401  # pragma: no cover

BLACK_HTML_STYLE = "color:#555555;text-align:center;font-size:200%;"  # pragma: no cover


def main():  # pragma: no cover
    try:
        alert = demisto.context().get("Core", {}).get("OriginalAlert")
        if isinstance(alert, list):
            alert = alert[0]
        if alert.get("raw_abioc") is None:
            event = alert.get("event")
        else:
            event = alert.get("raw_abioc").get("event")
        resourceType = event.get("resource_type_orig")

        html = f"<h1 style='{BLACK_HTML_STYLE}'>{resourceType!s}</h1>"

        return return_results(
            {
                "ContentsFormat": EntryFormat.HTML,
                "Type": EntryType.NOTE,
                "Contents": html,
            }
        )
    except Exception as e:
        return_error(f"An error occurred: {e!s}")


if __name__ in ["__main__", "builtin", "builtins"]:  # pragma: no cover
    return_results(main())  # pragma: no cover
