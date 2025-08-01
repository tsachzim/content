from __future__ import print_function  # noqa: UP010

import json
import logging
import uuid
import os

integrationContext = {}
is_debug = False  # type: bool
ARGS_COMMAND_PATH = os.path.join(os.path.dirname(__file__), ".args_command.json")

exampleIncidents = [
    {
        "Brand": "Builtin",
        "Category": "Builtin",
        "Contents": {
            "data": [
                {
                    "CustomFields": {},
                    "account": "",
                    "activated": "0001-01-01T00:00:00Z",
                    "attachment": None,
                    "autime": 1550670443962164000,
                    "canvases": None,
                    "category": "",
                    "closeNotes": "",
                    "closeReason": "",
                    "closed": "0001-01-01T00:00:00Z",
                    "closingUserId": "",
                    "created": "2019-02-20T15:47:23.962164+02:00",
                    "details": "",
                    "droppedCount": 0,
                    "dueDate": "2019-03-02T15:47:23.962164+02:00",
                    "hasRole": False,
                    "id": "1",
                    "investigationId": "1",
                    "isPlayground": False,
                    "labels": [
                        {"type": "Instance", "value": "test"},
                        {"type": "Brand", "value": "Manual"},
                    ],
                    "lastOpen": "0001-01-01T00:00:00Z",
                    "linkedCount": 0,
                    "linkedIncidents": None,
                    "modified": "2019-02-20T15:47:27.158969+02:00",
                    "name": "1",
                    "notifyTime": "2019-02-20T15:47:27.156966+02:00",
                    "occurred": "2019-02-20T15:47:23.962163+02:00",
                    "openDuration": 0,
                    "owner": "analyst",
                    "parent": "",
                    "phase": "",
                    "playbookId": "playbook0",
                    "previousRoles": None,
                    "rawCategory": "",
                    "rawCloseReason": "",
                    "rawJSON": "",
                    "rawName": "1",
                    "rawPhase": "",
                    "rawType": "Unclassified",
                    "reason": "",
                    "reminder": "0001-01-01T00:00:00Z",
                    "roles": None,
                    "runStatus": "waiting",
                    "severity": 0,
                    "sla": 0,
                    "sourceBrand": "Manual",
                    "sourceInstance": "amichay",
                    "status": 1,
                    "type": "Unclassified",
                    "version": 6,
                }
            ],
            "total": 1,
        },
        "ContentsFormat": "json",
        "EntryContext": None,
        "Evidence": False,
        "EvidenceID": "",
        "File": "",
        "FileID": "",
        "FileMetadata": None,
        "HumanReadable": None,
        "ID": "",
        "IgnoreAutoExtract": False,
        "ImportantEntryContext": None,
        "Metadata": {
            "brand": "Builtin",
            "category": "",
            "contents": "",
            "contentsSize": 0,
            "created": "2019-02-24T09:44:51.992682+02:00",
            "cronView": False,
            "endingDate": "0001-01-01T00:00:00Z",
            "entryTask": None,
            "errorSource": "",
            "file": "",
            "fileID": "",
            "fileMetadata": None,
            "format": "json",
            "hasRole": False,
            "id": "",
            "instance": "Builtin",
            "investigationId": "7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
            "modified": "0001-01-01T00:00:00Z",
            "note": False,
            "parentContent": '!getIncidents query="id:1"',
            "parentEntryTruncated": False,
            "parentId": "111@7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
            "pinned": False,
            "playbookId": "",
            "previousRoles": None,
            "recurrent": False,
            "reputationSize": 0,
            "reputations": None,
            "roles": None,
            "scheduled": False,
            "startDate": "0001-01-01T00:00:00Z",
            "system": "",
            "tags": None,
            "tagsRaw": None,
            "taskId": "",
            "times": 0,
            "timezoneOffset": 0,
            "type": 1,
            "user": "",
            "version": 0,
        },
        "ModuleName": "InnerServicesModule",
        "Note": False,
        "ReadableContentsFormat": "",
        "System": "",
        "Tags": None,
        "Type": 1,
        "Version": 0,
    }
]
exampleContext = [
    {
        "Brand": "Builtin",
        "Category": "Builtin",
        "Contents": {
            "context": {},
            "id": "1",
            "importantKeys": None,
            "modified": "2019-02-24T09:50:21.798306+02:00",
            "version": 30,
        },
        "ContentsFormat": "json",
        "EntryContext": None,
        "Evidence": False,
        "EvidenceID": "",
        "File": "",
        "FileID": "",
        "FileMetadata": None,
        "HumanReadable": None,
        "ID": "",
        "IgnoreAutoExtract": False,
        "ImportantEntryContext": None,
        "Metadata": {
            "brand": "Builtin",
            "category": "",
            "contents": "",
            "contentsSize": 0,
            "created": "2019-02-24T09:50:28.652202+02:00",
            "cronView": False,
            "endingDate": "0001-01-01T00:00:00Z",
            "entryTask": None,
            "errorSource": "",
            "file": "",
            "fileID": "",
            "fileMetadata": None,
            "format": "json",
            "hasRole": False,
            "id": "",
            "instance": "Builtin",
            "investigationId": "7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
            "modified": "0001-01-01T00:00:00Z",
            "note": False,
            "parentContent": '!getContext id="1"',
            "parentEntryTruncated": False,
            "parentId": "120@7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
            "pinned": False,
            "playbookId": "",
            "previousRoles": None,
            "recurrent": False,
            "reputationSize": 0,
            "reputations": None,
            "roles": None,
            "scheduled": False,
            "startDate": "0001-01-01T00:00:00Z",
            "system": "",
            "tags": None,
            "tagsRaw": None,
            "taskId": "",
            "times": 0,
            "timezoneOffset": 0,
            "type": 0,
            "user": "",
            "version": 0,
        },
        "ModuleName": "InnerServicesModule",
        "Note": False,
        "ReadableContentsFormat": "",
        "System": "",
        "Tags": None,
        "Type": 0,
        "Version": 0,
    }
]
exampleUsers = [
    {
        "Brand": "Builtin",
        "Category": "Builtin",
        "Contents": [
            {
                "accUser": False,
                "addedSharedDashboards": None,
                "canPostTicket": False,
                "dashboards": None,
                "defaultAdmin": True,
                "disableHyperSearch": False,
                "editorStyle": "",
                "email": "admintest@demisto.com",
                "helpSnippetDisabled": False,
                "homepage": "",
                "id": "admin",
                "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJAAAACQCAYAAADnRuK4AAAACXBIWXMAAB"
                "YlAAAWJQFJUiTwAAAFeElEQVR42u2dO1MbVxSAj2whIZAQHlWksSrcwKAMVWjYNLhiRjOkSYXyC7"
                "z5BfE/iNKmYWlchRnNyE2oRKO0y5DGaiI3pokcbRYNelopCDNOeGmlXS269/v6BcH9dPace+4jM"
                "hwOhwIwJk/4FwACAQIBAgECASAQIBAgECAQAAIBAgECAQIBIBAgECAQIBAAAgECAQIBAgECASAQIB"
                "AgECAQAAIBAgECAQIBIBAEQfSxfJBK74NY7ZrYg4ac9huMzD1sRDOSj2XFTKzLciQW6meJhH3AlN1"
                "viNmqyknvHDM8ko7E5PXCppiJdT0Fsto1+e6iggkTsh9fFStl6JUDIY9/HHZqUrw80ycC2f2GGE5Zn"
                "GGX0feRP559K9mnKfUjkNmqIk8AFNvTj0JTF8juN0iYA6LUqasvkNV5x0gHxPtPF1P/nVOfB7IfmON"
                "JR2JSWtoRY+6LmR/QgluRw05NaWmnHoEeen1ZKWPm5WkOu1rIE0oEeoh8LDvz8hhOWZvZdHphyINAyI"
                "NAyEMOpCe6z6oTgZCHCCRy1Zy1Ou9uTBNsz61IIf5CCvOryINAN6kPXMm7x3fmHye9cznpnUuxfSal1I"
                "4vzUbkUeQVVh+4kmsejZS8nvYbkmseSX3gThzpvmweIY8KAuXdY08D6Qy7knePJ5KHNUyKCGS1a2OVza"
                "f9hljtGvJoL9AEXX2vzyKPgkn0JGuKvDxrtqry0+XvmKJiDjQNkAeBAIEAgXxme24llGdBEYEK8RehPAu"
                "qCDS/KhvRjOfnNqIZ3/tiCDSjlFI7kvZwuEA6EpNSaodRR6Arsk9TYi/vjRSJNqIZsZf3pr5zE4FmRKK"
                "DpHFrcrw9tyIHSQN5AkKZ9UCF+VVyGyIQIBAgEAACAQIBAgECASAQIBAg0AiUunVGBYHu5qHFXAW3IpX"
                "eB0ZmRph6LywXzdy7K8IZduVr5y0jQwS6I8KwGjAw0iFcvDJ1gXLRDGuSAyKMw0lDSaKLi1uhfFtUx0"
                "ys6SFQLpqR4uIWI+4j+/FVfSKQyNUCsIOkwcj7wEY0I8VkOF9ILpybcV4l1kKN5qELdA1XXo7O8ydJ"
                "ycezYs6vh77O+9EI9FiJ/PnzxK+XSno39LtNlcuBdEls7eU9ZeUR4ZzowDhIGlrsEkEgn1HpuioEC"
                "qGc9usoYXIgDfOdSnpXu92vRCAf+GFhU14vbGr5tyPQhPmOlTJm/pI8BAqB50+SUlp6KbkxzihCIM"
                "3ZnluR0tJLped3SKID4lViTemZZSJQgOgyOYhAASTLlfSu9vkOAnmkOewq3wydFLrxQBINCAQIBAik"
                "CXa/IdmPb8a6ufAhrHZNsh/fiK3JslztkujmsCu5v36R958uRETkx8WvxEys+/Kzi5dn8n3rNxG5"
                "anXYz75RvnrTSqDmsCuGU76xaH8/vipWypjoZxfcihx2/hvRdJgC0OoVZl5Ub93xcdipieGUpTnG"
                "Vd7XUv5fHpGrC37Niyo5kBLytKq3DvI1J71zMZyyp3vl6wNXDKd87562w05NzJa6EmnxCvNy6/Ko"
                "bQu73xDDKY98b72qfTQtIlAumhn5MAfn31fSfRWa1a55kicdiSnbR9Mmia4PXMm7x552vd5WoX1"
                "eaY2C6gvttavC8n//6mkf/ucV2m2V1n3osPBMy2bqOCJcJ9rjiKcy2nbjvb6KvODn5CQCPfLqzGx"
                "R06GR0mWi4tbWq1a1H49kNdyfNLyH4Go0LSrtBAooApNl0oLgQKq0HSptBAogApNp0oLgXys0HSst"
                "BDIpwqN/WEINHaFJiLaVloI5EOFJiJsLkQg8Bu29QACAQIBAgECASAQIBAgECAQAAIBAgECAQIBIB"
                "AgECAQIBAAAgECAQLBLPMPFxalhUpzvrEAAAAASUVORK5CYII=",
                # noqa E501
                "investigationPage": "",
                "lastLogin": "0001-01-01T00:00:00Z",
                "name": "Admin Dude",
                "notify": ["mattermost", "email", "slack"],
                "phone": "+650-123456",
                "playgroundCleared": False,
                "playgroundId": "818df1a9-98dc-46df-84dc-dbd2fffc0fda",
                "preferences": {
                    "userPreferencesIncidentTableQueries": {
                        "Open Jobs in the last 7 days": {
                            "picker": {"predefinedRange": {"id": "7", "name": "Last 7 days"}},
                            "query": "-status:closed category:job",
                        },
                        "Open incidents in the last 7 days": {
                            "isDefault": True,
                            "picker": {"predefinedRange": {"id": "7", "name": "Last 7 days"}},
                            "query": "-status:closed -category:job",
                        },
                    },
                    "userPreferencesWarRoomFilter": {
                        "categories": [
                            "chats",
                            "incidentInfo",
                            "commandAndResults",
                            "notes",
                        ],
                        "fromTime": "0001-01-01T00:00:00Z",
                        "pageSize": 0,
                        "tagsAndOperator": False,
                        "usersAndOperator": False,
                    },
                    "userPreferencesWarRoomFilterExpanded": False,
                    "userPreferencesWarRoomFilterMap": {
                        "Chats only": {
                            "categories": ["chats"],
                            "fromTime": "0001-01-01T00:00:00Z",
                            "pageSize": 0,
                            "tagsAndOperator": False,
                            "usersAndOperator": False,
                        },
                        "Default Filter": {
                            "categories": [
                                "chats",
                                "incidentInfo",
                                "commandAndResults",
                                "notes",
                            ],
                            "fromTime": "0001-01-01T00:00:00Z",
                            "pageSize": 0,
                            "tagsAndOperator": False,
                            "usersAndOperator": False,
                        },
                        "Playbook results": {
                            "categories": [
                                "playbookTaskResult",
                                "playbookErrors",
                                "justFound",
                            ],
                            "fromTime": "0001-01-01T00:00:00Z",
                            "pageSize": 0,
                            "tagsAndOperator": False,
                            "usersAndOperator": False,
                        },
                    },
                    "userPreferencesWarRoomFilterOpen": True,
                },
                "roles": {"demisto": ["Administrator"]},
                "theme": "",
                "username": "admin",
                "wasAssigned": False,
            }
        ],
        "ContentsFormat": "json",
        "EntryContext": {
            "DemistoUsers": [
                {
                    "email": "admintest@demisto.com",
                    "name": "Admin Dude",
                    "phone": "+650-123456",
                    "roles": ["demisto: [Administrator]"],
                    "username": "admin",
                }
            ]
        },
        "Evidence": False,
        "EvidenceID": "",
        "File": "",
        "FileID": "",
        "FileMetadata": None,
        "HumanReadable": "## Users\nUsername|Email|Name|Phone|Roles\n-|-|-|-|-\nadmin|admintest@demisto.com|Admin Dude|"
        "\\+650-123456|demisto: \\[Administrator\\]\n",
        # noqa E501
        "ID": "",
        "IgnoreAutoExtract": False,
        "ImportantEntryContext": None,
        "Metadata": {
            "brand": "Builtin",
            "category": "",
            "contents": "",
            "contentsSize": 0,
            "created": "2019-02-24T09:50:28.686449+02:00",
            "cronView": False,
            "endingDate": "0001-01-01T00:00:00Z",
            "entryTask": None,
            "errorSource": "",
            "file": "",
            "fileID": "",
            "fileMetadata": None,
            "format": "json",
            "hasRole": False,
            "id": "",
            "instance": "Builtin",
            "investigationId": "7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
            "modified": "0001-01-01T00:00:00Z",
            "note": False,
            "parentContent": '!getUsers online="False"',
            "parentEntryTruncated": False,
            "parentId": "120@7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
            "pinned": False,
            "playbookId": "",
            "previousRoles": None,
            "recurrent": False,
            "reputationSize": 0,
            "reputations": None,
            "roles": None,
            "scheduled": False,
            "startDate": "0001-01-01T00:00:00Z",
            "system": "",
            "tags": None,
            "tagsRaw": None,
            "taskId": "",
            "times": 0,
            "timezoneOffset": 0,
            "type": 1,
            "user": "",
            "version": 0,
        },
        "ModuleName": "InnerServicesModule",
        "Note": False,
        "ReadableContentsFormat": "",
        "System": "",
        "Tags": None,
        "Type": 1,
        "Version": 0,
    }
]
exampleDemistoUrls = {
    "evidenceBoard": "https://test-address:8443/#/EvidenceBoard/7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
    "investigation": "https://test-address:8443/#/Details/7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
    "relatedIncidents": "https://test-address:8443/#/Cluster/7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
    "server": "https://test-address:8443",
    "warRoom": "https://test-address:8443/#/WarRoom/7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
    "workPlan": "https://test-address:8443/#/WorkPlan/7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
}
exampleAutoFocusApiKey = "1234"

callingContext = {}  # type: dict

contentSecrets = {
    "WildFire-Reports": {"token": "<ReplaceWithToken>"},
    "AutoFocusTagsFeed": {"api_key": "<ReplaceWithApiKey>"},
    "Http_Connector": {"token": "<ReplaceWithToken>", "url": "<ReplaceWithURL>"},
}


def initialize():
    """Runs some initializations to the demisto object. Should not be used in integration code"""


def params():
    """(Integration only)
    Retrieves the integration parameters object

    Returns:
      dict: Integrations parameters object

    """
    demisto_params = os.getenv("DEMISTO_PARAMS")
    if demisto_params:
        try:
            return json.loads(demisto_params)
        except json.JSONDecodeError:
            return {}
    return {}


def args():
    """Retrieves a command / script arguments object

    Returns:
      dict: Arguments object

    """
    if os.path.exists(ARGS_COMMAND_PATH):
        with open(ARGS_COMMAND_PATH) as f:
            try:
                args = json.load(f)
            except json.JSONDecodeError:
                return {}
            args.pop("cmd", None)
            return args
    return {}


def command():
    """(Integration only)
       Retrieves the integration command that is being run

    Returns:
      str: Integrations command name

    """
    if os.path.exists(ARGS_COMMAND_PATH):
        with open(ARGS_COMMAND_PATH) as f:
            try:
                return json.load(f)["cmd"]
            except json.JSONDecodeError:
                return ""
            except KeyError:
                return ""
    return ""


def log(msg):
    """Prints a message to the current incidents war room log

    Args:
      msg (str): The message to be logged

    Returns:
      None: No data returned
    """
    logging.getLogger().info(msg)


def get(obj, field, defaultParam=None):
    """Extracts field value from nested object

    Args:
      obj (dict): The object to extract the field from
      field (str): The field to extract from the object, given in dot notation
      defaultParam (object): The default value to return in case the field doesn't exist in obj

    Returns:
      str: The value of the extracted field

    """
    parts = field.split(".")
    for part in parts:
        if obj and part in obj:
            obj = obj[part]
        else:
            return defaultParam
    return obj


def gets(obj, field):
    """Extracts field value from nested object

    Args:
      obj (dict): The object to extract the field from
      field (str): The field to extract from the object, given in dot notation

    Returns:
      str: The value of the extracted field

    """
    return str(get(obj, field))


def context():
    """Retrieves the context data object of the current incident

    Returns:
      dict: Context data object

    """
    return {}


def uniqueFile():
    """Generate a unique file name based upon a random UUID

    Returns:
      str: Random UUID

    """
    return str(uuid.uuid4())


def getLastRun():
    """(Integration only)
    Retrieves the LastRun object

    Returns:
      dict: LastRun object

    """
    return {"lastRun": "2018-10-24T14:13:20+00:00"}


def setLastRun(obj):
    """(Integration only)
    Stores given object in the LastRun object

    Args:
      obj (dict): The object to store

    Returns:
      None: No data returned

    """
    return


def info(msg, *args):
    """Prints a message to the server logs in info level

    Args:
      msg (str): The message to be logged
      args (dict): Additional arguments to log

    Returns:
      None: No data returned

    """
    logging.getLogger().info(msg, *args)


def error(msg, *args):
    """Prints a message to the server logs in error level

    Args:
      msg (str): The message to be logged
      args (dict): Additional arguments to log

    Returns:
      None: No data returned

    """
    # print to stdout so pytest fail if not mocked
    print(msg, *args)  # noqa: T201


def debug(msg, *args):
    """Prints a message to the server logs in debug level

    Args:
      msg (str): The message to be logged
      args (dict): Additional arguments to log

    Returns:
      None: No data returned

    """
    logging.getLogger().info(msg, *args)


def getAllSupportedCommands():
    """(Script only)
    Retrieves all available integration commands and scripts

    Returns:
      dict: Object of all available integrations and scripts

    """
    return {}


def results(results):
    """Outputs entries to the war-room

    Args:
      results (Union[list, dict]): The entry object or array of entry objects to output

    Returns:
      None: No data returned

    An example of results argument:
    ```
    {
        Type: EntryType.NOTE,
        Contents: data,
        ContentsFormat: EntryFormat.JSON,
        HumanReadable: md,
        ReadableContentsFormat: EntryFormat.MARKDOWN,
        EntryContext: context,
        Tags: [tag1, tag2]
    }
    ```
    """
    if isinstance(results, dict) and results.get("contents"):
        results = results.get("contents")
    log("demisto results: {}".format(json.dumps(results, indent=4, sort_keys=True)))    # noqa: UP032


def credentials(credentials):
    """(Integration only)
    For integrations that support fetching credentials. Send the fetched credentials to the server.

    Args:
      credentials (list): List of credential objects

    Returns:
      None: No data returned

    """
    log("credentials: {}".format(credentials))  # noqa: UP032


def getFilePath(id):
    """Retrieves file path and name, given file entry ID

    Args:
      id (str): File entry ID to get details of

    Returns:
      dict: Object contains file ID, path and name

    """
    return {"id": id, "path": "test/test.txt", "name": "test.txt"}


def investigation():
    """Retrieves the ID of the investigation in which being run in


    Returns:
      dict: Object contains the investigation ID

    """
    return {"id": "1"}


def executeCommand(command, args):
    """(Script only)
    Executes given integration command / script and arguments

    Args:
      command (str): Integration command name or script name to run
      args (dict): Integration command / script arguments

    Returns:
      Union[dict, list]: Command execution response wrapped in Demisto entry object

    """
    commands = {
        "getIncidents": exampleIncidents,
        "getContext": exampleContext,
        "getUsers": exampleUsers,
    }
    if commands.get(command):
        return commands.get(command)

    return ""


def getParam(param):
    """(Integration only)
    Extracts given parameter from the integration parameters object

    Args:
      param (str): Integration parameter to get value of

    Returns:
      str: Integration parameter value

    """
    return params().get(param)


def getArg(arg):
    """Extracts given argument from the arguments object

    Args:
      arg (str): Argument to get value of

    Returns:
      str: Argument value

    """
    return args().get(arg)


def setIntegrationContext(context):
    """(Integration only)
    Stores given object in the IntegrationContext object

    Args:
      context (dict): The object to store

    Returns:
      None: No data returned

    """
    global integrationContext
    integrationContext = context


def getIntegrationContext():
    """(Integration only)
    Retrieves the IntegrationContext object

    Returns:
      dict: IntegrationContext object

    """
    return integrationContext


def setIntegrationContextVersioned(context, version=-1, sync=False):
    """(Integration only)
    Stores given object in the IntegrationContext object in given version

    Args:
      context (dict): The object to store
      version (int): The context version to set. If the version is older than the current, an error will be thrown. (Default value = -1)  # noqa
      sync (bool): Whether to save the context to the DB right away.
    If false, the context will be saved at the end of the command. (Default value = False)

    Returns:
      None: No data returned

    """  # noqa: E501
    global integrationContext
    integrationContext = context


def getIntegrationContextVersioned(refresh=False):
    """(Integration only)
    Retrieves the versioned IntegrationContext object

    Args:
      refresh (bool): Whether to get the integration context straight from the DB and not from the instance memory.
       (Default value = False) # noqa

    Returns:
      dict: IntegrationContext versioned object

    """
    return integrationContext


def incidents(incidents=None):
    """In script, retrieves the `Incidents` list from the context
    In integration, used to return incidents to the server.

    Args:
      incidents (list): In integration only, list of incident objects (Default value = None).

    Returns:
      list: List containing the current incident object.

    """
    if incidents is None:
        return exampleIncidents[0]["Contents"]["data"]  # type: ignore[index]
    else:
        return results({"Type": 1, "Contents": json.dumps(incidents), "ContentsFormat": "json"})


def incident():
    """Retrieves the current incident and all its fields (e.g. name, type).
    The incident custom fields will be populated as a `dict` under the CustomFields attribute
    (for example the `filename` custom field can be retrieved using `demisto.incident()['CustomFields'].get('filename')`).

    demisto.incident gets the data from the script on the beginning of the execution,
    hence if updating the incident context during script execution,
    it won't be reflected when calling demisto.incident, which will return stale context data.

    Returns:
      dict: dict representing an incident object

    """
    return incidents()[0]


def setContext(contextPath, value):
    """(Script only)
    Sets given value in path in the context data

    Args:
      contextPath (str): The context data path to set the value in
      value (str): The value to set in the context data path

    Returns:
      dict: Object contains operation result status

    """
    return {"status": True}


def demistoUrls():
    """Retrieves the following URLs related to the incident.
        - evidenceBoard
        - investigation
        - relatedIncidents
        - server
        - warRoom
        - workPlan
    You can use these URLs when you send notifications outside the system
    over email or slack and would like to include a link to the incident.


    Returns:
      dict: Object contains server URLs with page as key and URL as value

    """
    return exampleDemistoUrls


def getAutoFocusApiKey():
    """Retrieves the AutoFocus API Key related to this Cortex XSOAR License.
    You can use this API Key in all AutoFocus integrations and Feeds.
    This command is not available on tenants.


    Returns:
      str: String containing the API Key

    """
    return exampleAutoFocusApiKey


def dt(obj=None, trnsfrm=None):
    """Extracts field from object using DT language syntax

    Args:
      obj (dict): The object to look in for the requested field (Default value = None)
      trnsfrm (str): The field to get value of (Default value = None)

    Returns:
      str: The field value in the object

    """
    return ""


def addEntry(id, entry, username=None, email=None, footer=None):
    """(Integration only)
    Adds an entry to a mirrored investigation war room

    Args:
      id (str): Incident ID to add the entry in
      entry (str): The text to add in the entry
      username (str): The username of the user to be the entry creator (Default value = None)
      email (str): The email address of the user to be the entry creator (Default value = None)
      footer (str): The email address of the user to be the entry creator (Default value = None)

    Returns:
      None: No data returned

    """
    return ""


def mirrorInvestigation(id, mirrorType, autoClose=False):
    """(Integration only)
    Marks an investigation as mirrored

    Args:
      id (str): Incident ID to mirror
      mirrorType (str): Contains mirror type and mirror direction separated by colon, e.g. all:both
      autoClose (bool): Whether to close the investigation when the mirrored channel is closed/archived
       (Default value = False)

    Returns:
      None: No data returned

    """
    return ""


def updateModuleHealth(data, is_error=False):
    """(Integration only)
    Updated integration module health with given message

    Args:
      data (Union[str, dict]): Either the message to display in the integration module health,
        or a dictionary containing the "eventsPulled" field (number).
      is_error (bool): Whether or not to display it as an error message in the fetch history.

    Returns:
      None: No data returned

    """
    return ""


def directMessage(message, username=None, email=None, anyoneCanOpenIncidents=None):
    """(Integration only)
    Executes command provided in direct message to messaging bot

    Args:
      message (str): The message sent in personal context
      username (str): The username of the user that sent the direct message (Default value = None)
      email (str): The email address of the user that sent the direct message (Default value = None)
      anyoneCanOpenIncidents (bool): Whether external users can create incidents or not (Default value = None)

    Returns:
      str: Server response to command executed in the direct message

    """
    return ""


def createIncidents(incidents, lastRun=None, userID=None):
    """(Integration only)
    Creates incident in long running execution

    Args:
      incidents (list): List of incident objects to create, with the following optional keys:
            - name (str)
            - type (str) - If not provided, an Unclassified incident will be created
            - labels (list) - List of {"type": _, "value": _} objects
            - rawJSON (str) - Will be omitted after the classification & mapping step
            - occurred (str)
            - details (str)
            - severity (int)
      lastRun (dict): the LastRun object to set (Default value = None)
      userID (str): The user associated with the request (Default value = None)

    Returns:
      Union[list, dict]: Created incident object

    """
    return []


def findUser(username=None, email=None):
    """(Integration only)
    Looks up for a user in the system

    Args:
      username (str): The username of the user to search for (Default value = None)
      email (str): The email address of the user to search for (Default value = None)

    Returns:
      dict: Object representing the user found

    """
    return {}


def handleEntitlementForUser(incidentID, guid, email, content, taskID=""):
    """(Integration only)
    Sends request to server to process entitlement response given from messaging client

    Args:
      incidentID (str): The incident ID in which the question was sent in
      guid (str): The entitlement UUID which identifies the question
      email (str): The email address of the user that responded
      content (str): The content of the response
      taskID (str): The playbook task ID to mark as complete (Default value = "")

    Returns:
      None: No data returned

    """
    return {}


def demistoVersion():
    """Retrieves server version and build number

    Returns:
      dict: Objects contains server version and build number

    """
    return {"version": "5.5.0", "buildNumber": "12345"}


def integrationInstance():
    """(Integration only)
    Retrieves the integration instance name in which ran in

    Returns:
      str: The integration instance name

    """
    return ""


def createIndicators(indicators_batch, noUpdate=False):
    """(Integration only)
    Creates indicators from given indicator objects batch

    Args:
      indicators_batch (list): List of indicators objects to create
      noUpdate (bool): No update on fetched feed (no new indicators to fetch), Available from Server version 6.5.0.

    Returns:
      None: No data returned

    """
    return ""


def searchIndicators(
    fromDate="", query="", size=100, page=0, toDate="", value="", searchAfter=None, populateFields=None, **kwargs
):
    """Searches for indicators according to given query.
    If using Elasticsearch with Cortex XSOAR 6.1 or later,
    the searchAfter argument must be used instead of the page argument.

    Args:
      fromdate (str): The start date to search from (Default value = '')
      query (str): Indicator search query (Default value = '')
      size (int): Limit the number of returned results (Default value = 100)
      page (int): Response paging (Default value = 0)
      todate (str): The end date to search until to (Default value = '')
      value (str): The indicator value to search (Default value = '')
      searchAfter (list): Use the last searchIndicators() outputs for search batch (Default value = None)
      populateFields (str): Comma separated fields to filter (e.g. "value,type")

    Returns:
      dict: Object contains the search results

    You can searchIndicators one batch at a time, without needing to load all indicators at once, by adding the argument
    searchAfter after the demisto.executeCommand.
    When you run a search for the query type:IP, the return value includes searchAfter
    ```
    >>> demisto.executeCommand(searchIndicators, "query": 'type:IP', "size" :1000})
    {
        "iocs": [],
        "searchAfter": [1596106239679, dd7aa6abfcb3adf793922618005b2ad5],
        "total": 7432
    }
    ```
    You can then use the returned value of searchAfter to iterate over all batches.
    ```
    >>> res = demisto.executeCommand("searchIndicators", {"query" : 'type:IP', "size" : 1000})
    >>> search_after_title = 'searchAfter'
    >>> while search_after_title in res and res[search_after_title] is not None:
    >>>     demisto.results(res)
    >>>     res = demisto.executeCommand("searchIndicators",
    >>>                                 {"query" : 'type:IP', "size" : 1000, "searchAfter" : res[search_after_title]})
    ```
    """
    return {}


def getIndexHash():
    """(Integration only)
    Retrieves the hashed value of the tenant in which ran in

    Returns:
      str: Hashed value of tenant name

    """
    return ""


def getLicenseID():
    """Retrieves the ID of the license used in the server

    Returns:
      str: The license ID

    """
    return ""


def mapObject(obj, mapper, mapper_type):
    """Mapping an object using chosen mapper

    Returns:
      dict: the obj after mapping

    """
    return obj


def getModules():
    return {}


def get_incidents():
    return {}


def internalHttpRequest(method, uri, body=None):
    """Run an internal HTTP request to the XSOAR server. The request runs with the permissions of the
    executing user, when a command is being executed manually (such as via the War Room or when browsing a widget).
    When run via a playbook, will run with a readonly user with limited permissions isolated to the current incident only.
    Available for both Integrations and Scripts starting from Server version 6.1.

    Args:
        method (str): HTTP method such as: GET or POST
        uri (str): Server uri to request. For example: "/contentpacks/marketplace/HelloWorld".
        body Optional[str]: Optional body for a POST request. Defaults to None.

    Returns:
        dict: dict cotainnig the following fields:
        * statusCode (int): HTTP status code such as 200
        * status (str): HTTP status line such as: "200 OK"
        * body (str): response body
        * headers (dict): dict of headers. Each key is a header name with an array of values.
          For example: `"headers": {"Content-Type": ["text/plain; charset=utf-8"]}`
    """
    return {
        "statusCode": 404,
        "status": "404 Not Found",
        "body": "This is a mock. Your request was not found.",
        "headers": {
            "X-Xss-Protection": ["1; mode=block"],
            "X-Content-Type-Options": ["nosniff"],
            "Strict-Transport-Security": ["max-age=10886400000000000; includeSubDomains"],
            "Date": ["Wed, 27 Jan 2021 17:11:16 GMT"],
            "X-Frame-Options": ["DENY"],
            "Content-Type": ["text/plain; charset=utf-8"],
        },
    }


def parentEntry():
    """
    Retrieves information regarding the war room entry from which the method runs

    Returns:
      dict: information regarding the current war room entry

    """
    return {}


def getLastMirrorRun():
    """(Integration only)
    Retrieves the LastMirrorRun object

    Returns:
      dict: LastMirrorRun object

    """
    return {}


def setLastMirrorRun(obj):
    """(Integration only)
    Stores given object in the LastMirrorRun object

    Args:
      obj (dict): The object to store

    Returns:
      None: No data returned

    """
    return


def searchRelationships(args):
    """
    Retrieves Indicators Relationship data according to given filters.
    Args:
      args (dict): The relationships filter object.
        A dictionary with the following keys:
        - size (int)
        - relationshipNames (List[str])
        - entities (List[str])
        - entityTypes (List[str])
        - excludedEntities (List[str])
        - query (str)
        - fromDate (str)
        - toDate (str)
        - searchAfter (List[str])
        - searchBefore (List[str])
        - sort (List[Dict[str, Any]])

    Returns:
       (dict): The Relationship Search response.

    Example (partial results):
    ```
    >>> demisto.searchRelationships({"entities": ["8.8.8.8", "google.com"], "size": 2})
        {
        "total": 2,
        "data": [
            {
                "id": "27",
                "entityA": "8.8.8.8",
                "entityAFamily": "Indicator",
                "entityAType": "IP",
                "name": "contains",
                "reverseName": "part-of",
                "entityB": "1.1.1.1",
                "entityBFamily": "Indicator",
                "entityBType": "IP",
                "type": "IndicatorToIndicator",
                "createdInSystem": "2022-04-04T16:29:04.417942+03:00",
                "sources": [
                    {
                        "reliability": "C - Fairly reliable",
                    }
                ]
            },
            {
                "id": "26",
                "entityA": "google.com",
                "entityAFamily": "Indicator",
                "entityAType": "Domain",
                "name": "related-to",
                "reverseName": "related-to",
                "entityB": "bing.com",
                "entityBFamily": "Indicator",
                "entityBType": "Domain",
                "type": "IndicatorToIndicator",
                "createdInSystem": "2022-04-04T16:23:39.863033+03:00",
                "updatedInSystemBySource": "2022-04-04T16:23:39.862853+03:00",
                "sources": [
                    {
                        "reliability": "C - Fairly reliable",
                    }
                ]
            }
        ],
        "SearchAfter": [
            " \u0001\u0016q-\u0006`Uy'p",
            "26"
        ],
        "SearchBefore": [
            " \u0001\u0016q-\u0012\u0001\u0004n\u0013p",
            "27"
        ]
    }
    ```
    """
    return {"data": []}


def _apiCall(name=None, params=None, data=None, headers=None, method=None, path=None, timeout=None, response_data_type=None):
    """
    Special apiCall to internal xdr api. Only available to OOB content.

    Args:
        name: name of the api (currently only wfReportIncorrectVerdict is supported)
        params: url query args to pass. Use a dictionary such as: `{"key":"value"}
        data: POST data as a string. Make sure to json.dumps.
        headers: headers to pass. Use a dictionary such as: `{"key":"value"}`
        method: HTTP method to use.
        path: path to append to the base url.
        timeout: The amount of time (in seconds) that a request will wait for a client to send data before the request is aborted.
        response_data_type: The type of the response. should be None unless the response value is binary then it should be 'bin'.

        *Note if data is empty then a GET request is performed instead of a POST.

    Returns:
        dict: The response of the api call

    """
    return {}


def getLicenseCustomField(key):
    """
    Get a custom field from content XSOAR configuration (can only be run in system integrations)

    Args:
        key (str): The key name inside the content object to search for.

    Returns:
        str: the value stored in content object that matced the given key.
    """

    return get(contentSecrets, key)


def setAssetsLastRun(obj):
    """(Integration only)
    Stores given object in the AssetsLastRun object
    Args:
      obj (dict): The object to store
    Returns:
      None: No data returned
    """
    return


def getAssetsLastRun():
    return {"lastRun": "2018-10-24T14:13:20+00:00"}


def isTimeSensitive():
    """
    This function will indicate whether the command reputation (auto-enrichment) is called as auto-extract=inline.
    So for default the function return False.
    """
    return False




def _platformAPICall(path=None, method=None, params=None, data=None, timeout=None):
    """
    Special platform API call to interact with the platform's backend services. Only available to OOB content.
    Args:
        path: path to append to the base url
        method: HTTP method to use (GET, POST, PUT, DELETE, etc.)
        params: url query args to pass. Use a dictionary such as: `{"key":"value"}`
        data: POST data as a dict.
        timeout: The amount of time (in seconds) that a request will wait for a client to send data before the request is aborted
        *Note if data is empty then a GET request is performed instead of a POST.
    Returns:
        dict: The response of the api call
    """
    return {}