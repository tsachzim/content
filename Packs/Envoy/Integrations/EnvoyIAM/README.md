Integrate with Envoy Identity Access Management services to execute CRUD operations to employee lifecycle processes.
This integration was integrated and tested with version v2 of Envoy SCIM API.

## Configure Envoy IAM in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL |  | True |
| API Key |  | True |
| Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
| Use system proxy settings | Use system proxy settings. | False |
| Allow creating users |  | False |
| Allow updating users |  | False |
| Allow enabling users |  | False |
| Allow disabling users |  | False |
| Automatically create user if not found in update command |  | False |
| Incoming Mapper |  | True |
| Outgoing Mapper |  | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### iam-create-user

***
Creates a user.

#### Base Command

`iam-create-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | User Profile indicator details. | Required |
| allow-enable | When set to true, after the command execution the status of the user in the 3rd-party integration will be active. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active in the 3rd-party integration. |
| IAM.Vendor.brand | String | Name of the integration. |
| IAM.Vendor.details | string | Provides the raw data from the 3rd-party integration. |
| IAM.Vendor.email | String | The employee's email address. |
| IAM.Vendor.errorCode | Number | HTTP error response code. |
| IAM.Vendor.errorMessage | String | Reason why the API failed. |
| IAM.Vendor.id | String | The employee's user ID in the app. |
| IAM.Vendor.instanceName | string | Name of the integration instance. |
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. |
| IAM.Vendor.username | String | The employee's username in the app. |

#### Command Example

``` !iam-create-user user-profile=`{"email": "john.doe@example.com", "givenname": "test", "surname": "test"}` ```

#### Human Readable Output

### iam-update-user

***
Updates an existing user with the data passed in the user-profile argument.

#### Base Command

`iam-update-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required |
| allow-enable | When set to true, after the command execution the status of the user in the 3rd-party integration will be active. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active in the 3rd-party integration. |
| IAM.Vendor.brand | String | Name of the integration. |
| IAM.Vendor.details | string | Provides the raw data from the 3rd-party integration. |
| IAM.Vendor.email | String | The employee's email address. |
| IAM.Vendor.errorCode | Number | HTTP error response code. |
| IAM.Vendor.errorMessage | String | Reason why the API failed. |
| IAM.Vendor.id | String | The employee's user ID in the app. |
| IAM.Vendor.instanceName | string | Name of the integration instance. |
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. |
| IAM.Vendor.username | String | The employee's username in the app. |

#### Command Example

``` !iam-update-user user-profile=`{"email": "john.doe@example.com", "givenname": "John"}` ```

#### Human Readable Output

### iam-get-user

***
Retrieves a single user resource.

#### Base Command

`iam-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active in the 3rd-party integration. |
| IAM.Vendor.brand | String | Name of the integration. |
| IAM.Vendor.details | string | Provides the raw data from the 3rd-party integration. |
| IAM.Vendor.email | String | The employee's email address. |
| IAM.Vendor.errorCode | Number | HTTP error response code. |
| IAM.Vendor.errorMessage | String | Reason why the API failed. |
| IAM.Vendor.id | String | The employee's user ID in the app. |
| IAM.Vendor.instanceName | string | Name of the integration instance. |
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. |
| IAM.Vendor.username | String | The employee's username in the app. |

#### Command Example

``` !iam-get-user user-profile=`{"email": "john.doe@example.com"}` ```

#### Human Readable Output

### iam-disable-user

***
Disable an active user.

#### Base Command

`iam-disable-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | When true, indicates that the employee's status is active in the 3rd-party integration. |
| IAM.Vendor.brand | String | Name of the integration. |
| IAM.Vendor.details | string | Provides the raw data from the 3rd-party integration. |
| IAM.Vendor.email | String | The employee's email address. |
| IAM.Vendor.errorCode | Number | HTTP error response code. |
| IAM.Vendor.errorMessage | String | Reason why the API failed. |
| IAM.Vendor.id | String | The employee's user ID in the app. |
| IAM.Vendor.instanceName | string | Name of the integration instance. |
| IAM.Vendor.success | Boolean | When true, indicates that the command was executed successfully. |
| IAM.Vendor.username | String | The employee's username in the app. |

#### Command Example

``` !iam-disable-user user-profile=`{"email": "john.doe@example.com", "givenname": "John"}` ```

#### Human Readable Output
