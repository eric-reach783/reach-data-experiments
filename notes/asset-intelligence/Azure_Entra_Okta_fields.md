# Entra & Okta

<!-- TOC -->
* [Entra & Okta](#entra--okta)
      * [Jupyter Notebook](#jupyter-notebook)
    * [Field Mapping Considerations](#field-mapping-considerations)
      * [Caveats](#caveats)
    * [Field Mapping Additional Information](#field-mapping-additional-information)
        * [ID String Normalization](#id-string-normalization)
      * [Azure Licensing](#azure-licensing)
  * [Joinable Fields Between Entra Audit logs and signIns with Okta](#joinable-fields-between-entra-audit-logs-and-signins-with-okta)
    * [MS Graph API signIns Schema](#ms-graph-api-signins-schema)
    * [Okta System Logs Schema](#okta-system-logs-schema)
  * [Joinable Entra Fields & Okta](#joinable-entra-fields--okta)
<!-- TOC -->

#### Jupyter Notebook

This notebook contains some examples of using the joinable field table mappings.
- [notebook](../../notebooks/Entra_Okta_joins.ipynb)

### Field Mapping Considerations

* Field Mapping Requirements, structure or type conversion needed
  * Direct field-to-field mapping requires transformation logic due to different data types and structures
* Temporal Correlation, alignment of the time fields formats is needed
  * Both platforms use UTC timestamps, enabling time-based correlation
* Identity Correlation, user/service principal
  * User identification requires mapping between Azure user IDs and Okta actor IDs
* Application Context, application-specific/centric joins
  * Application correlation depends on consistent naming conventions between platforms
* Data Completeness or licensing caveats
  * Some Azure fields require premium licensing P1/P2 (risk.*) and may not be available in all environments, certain 
    Okta enrichments require Identity Threat Protection (user.risk.detect)

#### Caveats

This assumes certain fields, like `target[].id` for Okta logs when `type` is an application, have been migrated to Entra
from Okta. The `appId` field in the Graph API for `/applications` can then be joined on. Okta application identifiers (
like `target[].id` for apps or `client.id` for OAuth clients) need manual or programmatic migration/input into Microsoft
Entra ID.

### Field Mapping Additional Information

* Fields such as Azure `servicePrincipal.id` and Okta `client.id` resemble each other but need normalization
  * The Okta `client.id` is the public identifier required by all OAuth flows. This identifier is randomly generated 
    when you create the app integration
  * The Entra principalId is the ID of the client (user, group, or service principal) receiving the permission 
  * The Entra resourceId is the ID of the resource’s service principal that defines the app role
* In hybrid setups, Okta may sync objectGUID into Entra’s immutableId, but errors in mapping can lead to mismatched IDs
  that don’t align if the federation conflicts or incomplete sync can break correlation
  * Okta uses the immutableId attribute to correlate users between Okta and Microsoft Entra (Azure AD). They take the on‑premises Active Directory objectGUID, convert it to a base‑64 string, and stamp it into Azure AD’s immutableId field
* Every event in the Okta System Log has a unique uuid field that identifies the log entry itself. This ID is a
  version‑4 UUID (random) following the RFC 4122 standard

##### ID String Normalization

* Convert Azure GUIDs to lowercase strings to match Okta string IDs
* Flatten Okta target[] arrays before joining on appId/resourceId
* Possibly enumeration strings for success/failure (status.success vs. outcome.result)

#### Azure Licensing

* Premium 1 (P1) license is mandatory for each user whose sign-in, provisioning, MFA, dynamic group membership, or
  custom attribute
  data is accessed via Graph.
* Premium 2 (P2) is additionally required for risk-based conditional access, Identity Protection, PIM, and access
  reviews.

## Joinable Fields Between Entra Audit logs and signIns with Okta

Fields that can be either directly joined, and those that can be joined with data transformations for the Audit logs,
signIns, and Okta system Logs. The `Mapping  Rules` are examples of how these fields _may_ be joined together based on 
documentation.

<details>

| Azure Field                               | Data Type        | API Source (Azure)                          | Okta Field                                     | Data Type        | API Source (Okta)     | Mapping Rules                                        |
|-------------------------------------------|------------------|---------------------------------------------|------------------------------------------------|------------------|-----------------------|------------------------------------------------------|
| correlationId                             | string (GUID)    | auditLogs/signIns                           | uuid                                           | string           | logs (System Log API) | Lowercase; use as opaque string                      |
| createdDateTime / activityDateTime        | string (ISO8601) | auditLogs/signIns;auditLogs/directoryAudits | published                                      | string (ISO8601) | logs (System Log API) | Both in ISO 8601 UTC (timestamp)                     |
| userId                                    | string (GUID)    | auditLogs/signIns                           | actor.id                                       | string           | logs (System Log API) | Store as string for join                             |
| userPrincipalName                         | string           | auditLogs/signIns                           | actor.alternateId                              | string           | logs (System Log API) | Exact or lowercased string match                     |
| userDisplayName                           | string           | auditLogs/signIns                           | actor.displayName                              | string           | logs (System Log API) | Case-insensitive                                     |
| ipAddress / ipAddressFromResourceProvider | string (IPv4/6)  | auditLogs/signIns                           | client.ip                                      | string           | logs (System Log API) | Compare canonicalized strings                        |
| appDisplayName                            | string           | auditLogs/signIns                           | target[].displayName                           | string           | logs (System Log API) | Join where Okta target[].type=‘App’                  |
| appId                                     | string (GUID)    | auditLogs/signIns                           | target[].id                                    | string           | logs (System Log API) | Use if mapping exists (App GUID to App ID)           |
| result                                    | string/enum/int  | auditLogs/signIns                           | outcome.result                                 | string           | logs (System Log API) | Map Entra error codes to Okta enums e.g. 0 = SUCCESS |
| resultReason                              | string           | auditLogs/signIns                           | outcome.reason                                 | string           | logs (System Log API) | Case-insensitive                                     |
| deviceDetail.deviceId                     | string           | auditLogs/signIns                           | client.device (string, sometimes missing)      | string           | logs (System Log API) | Join if device IDs are tracked                       |
| clientAppUsed                             | string           | auditLogs/signIns                           | client.userAgent.browser                       | string           | logs (System Log API) | Map via string or lookup table when app = browser    |
| location.countryOrRegion(in location)     | string           | auditLogs/signIns.location                  | client.geographicalContext.country             | string           | logs (System Log API) | ISO country code match                               |
| location.city(in location)                | string           | auditLogs/signIns.location                  | client.geographicalContext.city                | string           | logs (System Log API) | Direct string case-insensitive                       |
| sessionId                                 | string           | auditLogs/signIns.sessionId                 | authenticationContext.externalSessionId        | string           | logs (System Log API) | String match                                         |
| resourceId                                | string (GUID)    | auditLogs/signIns                           | target[].id (when type is 'Resource' or 'App') | string           | logs (System Log API) | Join where type semantics match                      |
| additionalDetails                         | object / dict    | auditLogs/signIns                           | debugContext.debugData                         | object           | logs (System Log API) | Compare as needed (key-value map)                    |
| category (directory audit only)           | string           | auditLogs/directoryAudits                   | eventType                                      | string           | logs (System Log API) | Map functional/logical categories                    |

</details>

### MS Graph API signIns Schema

<details>

```json
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns",
  "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1&$skiptoken=9177f2e3532fcd4c4d225f68f7b9bdf7_1",
  "value": [
    {
      "id": "66ea54eb-6301-4ee5-be62-ff5a759b0100",
      "createdDateTime": "2023-12-01T16:03:35Z",
      "userDisplayName": "Test Contoso",
      "userPrincipalName": "testaccount1@contoso.com",
      "userId": "26be570a-ae82-4189-b4e2-a37c6808512d",
      "appId": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
      "appDisplayName": "Graph explorer",
      "ipAddress": "131.107.159.37",
      "clientAppUsed": "Browser",
      "correlationId": "d79f5bee-5860-4832-928f-3133e22ae912",
      "conditionalAccessStatus": "notApplied",
      "isInteractive": true,
      "riskDetail": "none",
      "riskLevelAggregated": "none",
      "riskLevelDuringSignIn": "none",
      "riskState": "none",
      "riskEventTypes": [],
      "resourceDisplayName": "Microsoft Graph",
      "resourceId": "00000003-0000-0000-c000-000000000000",
      "status": {
        "errorCode": 0,
        "failureReason": null,
        "additionalDetails": null
      },
      "deviceDetail": {
        "deviceId": "",
        "displayName": null,
        "operatingSystem": "Windows 10",
        "browser": "Edge 80.0.361",
        "isCompliant": null,
        "isManaged": null,
        "trustType": null
      },
      "location": {
        "city": "Redmond",
        "state": "Washington",
        "countryOrRegion": "US",
        "geoCoordinates": {
          "altitude": null,
          "latitude": 47.68050003051758,
          "longitude": -122.12094116210938
        }
      },
      "appliedConditionalAccessPolicies": [
        {
          "id": "de7e60eb-ed89-4d73-8205-2227def6b7c9",
          "displayName": "SharePoint limited access for guest workers",
          "enforcedGrantControls": [],
          "enforcedSessionControls": [],
          "result": "notEnabled"
        },
        {
          "id": "6701123a-b4c6-48af-8565-565c8bf7cabc",
          "displayName": "Medium signin risk block",
          "enforcedGrantControls": [],
          "enforcedSessionControls": [],
          "result": "notEnabled"
        }
      ]
    }
  ]
}
```
</details>

### Okta System Logs Schema

<details>
Example of the schema for the Okta System Logs API response:

```json
[
  {
    "actor": {
      "id": "00uttidj01jqL21aM1d6",
      "type": "User",
      "alternateId": "john.doe@example.com",
      "displayName": "John Doe",
      "detailEntry": null
    },
    "client": {
      "userAgent": {
        "rawUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "os": "Mac OS X",
        "browser": "CHROME"
      },
      "zone": null,
      "device": "Computer",
      "id": null,
      "ipAddress": "10.0.0.1",
      "geographicalContext": {
        "city": "New York",
        "state": "New York",
        "country": "United States",
        "postalCode": 10013,
        "geolocation": {
          "lat": 40.3157,
          "lon": -74.01
        }
      }
    },
    "device": {
      "id": "guofdhyjex1feOgbN1d9",
      "name": "Mac15,6",
      "os_platform": "OSX",
      "os_version": "14.6.0",
      "managed": false,
      "registered": true,
      "device_integrator": null,
      "disk_encryption_type": "ALL_INTERNAL_VOLUMES",
      "screen_lock_type": "BIOMETRIC",
      "jailbreak": null,
      "secure_hardware_present": true
    },
    "authenticationContext": {
      "authenticationProvider": null,
      "credentialProvider": null,
      "credentialType": null,
      "issuer": null,
      "interface": null,
      "authenticationStep": 0,
      "rootSessionId": "idxBager62CSveUkTxvgRtonA",
      "externalSessionId": "idxBager62CSveUkTxvgRtonA"
    },
    "displayMessage": "User login to Okta",
    "eventType": "user.session.start",
    "outcome": {
      "result": "SUCCESS",
      "reason": null
    },
    "published": "2024-08-13T15:58:20.353Z",
    "securityContext": {
      "asNumber": 394089,
      "asOrg": "ASN 0000",
      "isp": "google",
      "domain": null,
      "isProxy": false
    },
    "severity": "INFO",
    "debugContext": {
      "debugData": {
        "requestId": "ab609228fe84ce59cdcbfa690bcce016",
        "requestUri": "/idp/idx/authenticators/poll",
        "url": "/idp/idx/authenticators/poll"
      }
    },
    "legacyEventType": "core.user_auth.login_success",
    "transaction": {
      "type": "WEB",
      "id": "ab609228fe84ce59cdcbfa690bgce016",
      "detail": null
    },
    "uuid": "dc9fd3c0-598c-11ef-8478-2b7584bf8d5a",
    "version": 0,
    "request": {
      "ipChain": [
        {
          "ip": "10.0.0.1",
          "geographicalContext": {
            "city": "New York",
            "state": "New York",
            "country": "United States",
            "postalCode": 10013,
            "geolocation": {
              "lat": 40.3157,
              "lon": -74.01
            }
          },
          "version": "V4",
          "source": null
        }
      ]
    },
    "target": [
      {
        "id": "pfdfdhyjf0HMbkP2e1d7",
        "type": "AuthenticatorEnrollment",
        "alternateId": "unknown",
        "displayName": "Okta Verify",
        "detailEntry": null
      },
      {
        "id": "0oatxlef9sQvvqInq5d6",
        "type": "AppInstance",
        "alternateId": "Okta Admin Console",
        "displayName": "Okta Admin Console",
        "detailEntry": null
      }
    ]
  }
]
```
</details>


## Joinable Entra Fields & Okta

This section shows the fields between Azure Entras fields from other endpoints from the Graph APIs and Okta System Logs.

<details>

| Azure Field         | Data Type     | Azure API Endpoint                | Okta Field                                 | Data Type | Okta API Endpoint | Mapping Rules                                                                          |
|---------------------|---------------|-----------------------------------|--------------------------------------------|-----------|-------------------|----------------------------------------------------------------------------------------|
| id                  | string (GUID) | /users                            | actor.id                                   | string    | /api/v1/logs      | Lowercase GUID; exact match                                                            |
| userPrincipalName   | string        | /users                            | actor.alternateId                          | string    | /api/v1/logs      | Exact string match (email format)                                                      |
| displayName         | string        | /users                            | actor.displayName                          | string    | /api/v1/logs      | Possibly case-insensitive match                                                        |
| id                  | string (GUID) | /groups                           | target[].id                                | string    | /api/v1/logs      | Group ID join when type=Group                                                          |
| displayName         | string        | /groups                           | target[].displayName                       | string    | /api/v1/logs      | Display name match                                                                     |
| appId               | string (GUID) | /applications                     | target[].id (when type = App)              | string    | /api/v1/logs      | Requires Okta applications migration to Entra ID                                       |
| displayName         | string        | /applications                     | target[].displayName                       | string    | /api/v1/logs      | Standardized/canonicalized app names, requires Okta applications migration to Entra ID |
| id                  | string (GUID) | /servicePrincipals                | client.id or target[].id                   | string    | /api/v1/logs      | Azure SP ID to Okta OIDC client app join requires mapping                              |
| city                | string        | /signIns.location.city            | client.geographicalContext.city            | string    | /api/v1/logs      | Possibly case-insensitive match                                                        |
| countryOrRegion     | string        | /signIns.location.countryOrRegion | client.geographicalContext.country         | string    | /api/v1/logs      | ISO code match                                                                         |
| ipAddress           | string        | /signIns.ipAddress                | client.ip                                  | string    | /api/v1/logs      | IPv4/IPv6                                                                              |
| authenticationAppId | string (GUID) | /servicePrincipals.appId          | client.id or authenticationContext.authnId | string    | /api/v1/logs      | Possible join via app registration, requires Okta applications migration to Entra ID   |

</details>

Example of joining Okta event targeting an app (target[].id), you would:

    Capture the ID and type (e.g., "App") from the Okta log.

    Query GET /applications?$filter=appId eq '{ID}' in Azure.

    Retrieve the canonical display name or service principal ID for correlation.

Sources:

- https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0 - signIn resource type properties (
  Graph v1.0)
- https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/migrate-applications-from-okta - Migrating Okta 
  Applications to Entra ID
- https://help.okta.com/oie/en-us/content/topics/miscellaneous/ms-entra-id-migration/prepare-to-migrate.htm - 
  Migrate Okta Users to Entra ID
- https://cdn.cdata.com/help/CJJ/xls/pg_table-directoryaudits.htm - directoryAudit resource type columns
- https://cdn.cdata.com/help/CJK/py/pg_table-directoryaudits.htm
- https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0&tabs=http - List SignIns Graph API - P1 or
  P2 license required
- https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/response-format
- https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/ - System Log API schema (Okta
  Dev Docs)
- https://developer.okta.com/docs/reference/system-log-query/ - System log query reference (Okta)
- https://developer.okta.com/docs/reference/api/event-types/ - Event-type catalog (Okta)
- https://www.elastic.co/docs/reference/beats/filebeat/exported-fields-okta - Elastic “exported-fields-okta” mappings
- https://www.rezonate.io/blog/okta-logs-decoded-unveiling-identity-threats-through-threat-hunting/
- https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0 - Azure Intune
  device data
- https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing - Azure Entra Licensing plans
- https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http - Graph API List Users
  - User objects and attributes (id, userPrincipalName, displayName, mail, etc.)
- https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http - Graph API List Groups
  - Groups and their membership information
- https://learn.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0 - Graph API Application 
  Resource Type
  - Enterprise applications data (appId, displayName, etc.)
- https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0 - Graph API 
  servicePrinciple Resource Type
  - servicePrincipals Service principals data (id, appId, displayName, etc.)
- https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_oidc.htm - Okta OpenID Connect (OIDC) 
  App integrations
- https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0 - 
  Graph API oAuth2PermissionGrant resource type
- https://docs.azure.cn/en-us/data-explorer/kusto/query/datatypes-string-operators?view=microsoft-fabric#what-is-a-term 
- https://support.okta.com/help/s/article/ms-o365-federation-immutableid-missing-issue-with-o365-federation?
  language=en_US - Issues migrating Okta data to Entra, specifically around the IDs.
- https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/migrate-okta-sync-provisioning - Migrate Okta sync
  provisioning to Microsoft Entra Connect synchronization - ImmutableID
- https://support.okta.com/help/s/article/Will-the-Okta-User-ID-be-unique-across-all-Okta-instances?language=en_US - 
  Okta User Id and Application ID
- [Azure VS On-Premises AD](../../notes/asset-intelligence/Azure_vs_onprem.md)
- [Okta Fields](../../notes/asset-intelligence/Okta%20Fields.md)
