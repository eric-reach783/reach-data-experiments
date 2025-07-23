# Conditional Access Control

This docoument outlines the fields for CAC for Okta, Entra, AD, CrowdStrike.

Not all information was able to be found.

## Okta

- based on policies and rules
- Event based policies using System Log API
- Device based policies using device trust elavation

Schema Example:

```json
{
   "actor": {
      "id": "string",
      "type": "User|Client",
      "alternateId": "string",
      "displayName": "string"
   },
   "client": {
      "userAgent": {
         "rawUserAgent": "string",
         "os": "string",
         "browser": "string"
      },
      "device": "string",
      "id": "string",
      "ipAddress": "string",
      "geographicalContext": {
         "city": "string",
         "state": "string",
         "country": "string"
      }
   },
   "request": {
      "ipChain": [
         {
            "ip": "string",
            "geographicalContext": {},
            "version": "V4|V6",
            "source": "string"
         }
      ]
   },
   "outcome": {
      "result": "SUCCESS|FAILURE|SKIPPED|ALLOW|DENY",
      "reason": "string"
   }
}
```

Sources:

- https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
- https://developer.okta.com/docs/reference/api/event-types/
- https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Schema/

## Entra/Azure AD

- conditionalAccessPolicy - uses this resource type MS Graph API
- "Azure AD Conditional Access" is now "Microsoft Entra Conditional Access"

Schema:

```json
{
   "@odata.type": "#microsoft.graph.conditionalAccessPolicy",
   "id": "string",
   "displayName": "string",
   "state": "enabled|disabled|enabledForReportingButNotEnforced",
   "conditions": {
      "applications": {
         "includeApplications": [
            "string"
         ],
         "excludeApplications": [
            "string"
         ]
      },
      "users": {
         "includeUsers": [
            "string"
         ],
         "excludeUsers": [
            "string"
         ],
         "includeGroups": [
            "string"
         ],
         "excludeGroups": [
            "string"
         ]
      },
      "locations": {
         "includeLocations": [
            "string"
         ],
         "excludeLocations": [
            "string"
         ]
      },
      "devices": {
         "includeDevices": [
            "string"
         ],
         "excludeDevices": [
            "string"
         ]
      },
      "clientApps": [
         "string"
      ],
      "platforms": {
         "includePlatforms": [
            "string"
         ],
         "excludePlatforms": [
            "string"
         ]
      }
   },
   "grantControls": {
      "operator": "AND|OR",
      "builtInControls": [
         "string"
      ],
      "customAuthenticationFactors": [
         "string"
      ],
      "termsOfUse": [
         "string"
      ]
   },
   "sessionControls": {
      "applicationEnforcedRestrictions": {},
      "cloudAppSecurity": {},
      "signInFrequency": {},
      "persistentBrowser": {}
   }
}
```

Sources:

- https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-common
- https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/entra/fundamentals/new-name#naming-changes-and-exceptions

## Active Directory - On-premise

does not have "conditional access" in the current sense Verify this

- Device based CA
- Client Access Control policies - policy based using AD Federated Services
- Claim based authentication
-

#### Normal AD Capabilities:

- Group Policy-based controls (static policies)
- Network location restrictions (IP-based)
- Time-based logon restrictions
- Workstation/device restrictions

Schema:

```json
{
   "authenticationPolicy": {
      "name": "string",
      "userAllowedToAuthenticateFrom": "string",
      "userAllowedToAuthenticateTo": "string",
      "computerAllowedToAuthenticateFrom": "string",
      "serviceAllowedToAuthenticateFrom": "string"
   },
   "groupPolicy": {
      "distinguishedName": "string",
      "displayName": "string",
      "gpcFileSysPath": "string",
      "gpcFunctionalityVersion": "integer",
      "objectClass": "groupPolicyContainer"
   }
}
```

### Federated Services

Active Directory Federation Service (AD FS) enables Federated Identity and Access Management by securely sharing digital
identity and entitlements rights across security and enterprise boundaries. AD FS extends the ability to use single
sign-on functionality that is available within a single security or enterprise boundary to Internet-facing applications
to enable customers, partners, and suppliers a streamlined user experience while accessing the web-based applications of
an organization.

#### AD FS Conditional Access vs. Azure AD Conditional Access:

* AD FS: Basic device-based conditional access, requires device registration with on-premises infrastructure
* Azure AD: Advanced risk-based policies with real-time assessment, device compliance, location intelligence, and
  application-specific controls

Sources:

- https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configure-device-based-conditional-access-on-premises
- https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/ad-fs-client-access-policies

## CrowdStrike

CrowdStrike

Uses FALCON for identity threat protection and conditional access

`DCInfo/CS-DCInfo.ps1` - This PowerShell script was developed to obtain all relevant domain controller information. This
can be helpful when deploying Falcon Identity Protection.

The script gathers information such as Hostname, Global Catalog status, Site, Forest, Operation Master Roles, Drive
Letters, Disk Used/Free, etc., and exports these details to a CSV file. There is no reference to a conditional access
schema or related configuration in the code or documentation.

EventType Schema:

```json
eventType: Identity-based Detection
{
"meta": {
"query_time": 0.004553092,
"writes": {
"resources_affected": 0
},
"powered_by": "detectsapi",
"trace_id": "*"
},
"errors": [],
"resources": [
{
"eventType": "idp",
"activity_id": "*",
"aggregate_id": "*",
"cid": "*",
"composite_id": "dca1-XXXX-*",
"confidence": 30,
"context_timestamp": "2022-05-15T10:32:00.000Z",
"created_timestamp": "2022-05-15T11:34:56.887790892Z",
"description": "User access from an unusual location",
"display_name": "Unusual user geolocation",
"end_time": "2022-05-15T10:32:00.000Z",
"falcon_host_link": "https://falcon.crowdstrike.com/*",
"id": "*",
"location_country_code": "US",
"name": "AnomalousGeoLocationAccess",
"objective": "Gain Access",
"okta_application_id": "*",
"pattern_id": 51125,
"product": "idp",
"scenario": "machine_learning",
"severity": 31,
"show_in_ui": true,
"source_account_name": "*.*@*.*",
"source_account_okta_id": "*",
"source_endpoint_address_ip4": "*.*.*.*",
"source_endpoint_ip_address": "*.*.*.*",
"sso_application_identifier": "Okta * Console",
"sso_application_uri": "*",
"start_time": "2022-05-15T10:32:00.000Z",
"status": "new",
"tactic": "Initial Access",
"tactic_id": "*",
"technique": "Valid Accounts",
"technique_id": "T1078",
"timestamp": "2022-05-15T10:34:56.509Z",
"type": "idp-session-source-user-endpoint-target-info",
"updated_timestamp": "2022-05-15T11:34:56.887790892Z"
}
]
}
```

CrowdStrike Device Schema:

```JSON
    {
        "device_id": "ec548c991d46407c44a6cf5667858cfe",
        "external_ip": "142.215.176.54",
        "hostname": "HFDCCROWELL10VM",
        "last_login_timestamp": "2025-04-21T10:59:08Z",
        "last_login_user": "eubp618",
        "last_login_user_sid": "S-1-5-21-37255948-3494488630-3846078981-3111",
        "mac_address": "00-50-56-ae-12-5d",
        "os_version": "Windows 10",
        "platform_name": "Windows"
    }
  ```

Sources:
- https://www.oddsandendpoints.co.uk/posts/custom-compliance-third-party-av/
- https://docs.d3security.com/integration-docs/integration-docs/crowdstrike-identity-protection#:~:text=eventtype%3A
  %20identity-based%20detection - EventType Schema
- https://github.com/CrowdStrike/Identity-Protection/blob/main/DCInfo/CS-DCInfo.ps1
- https://www.crowdstrike.com/content/dam/crowdstrike/www/en-us/wp/2021/06/crowdstrike-falcon-identity-protecton-modules.pdf
- https://go.crowdstrike.com/rs/281-OBQ-266/images/WhitepaperPreemptConditionalAccess.pdf
- https://developer.crowdstrike.com/docs/openapi/ -- Need login to access
- https://falconpy.io/ -- python sdk
- https://www.dlt.com/sites/default/files/resource-attachments/2019-09/Datasheet---CrowdStrike-Falcon-APIs-Oct-2017_13.pdf
- https://www.crowdstrike.com/wp-content/uploads/2020/07/CrowdStrike-Falcon-Event-Streams-Add-on-Guide.pdf - Explains
  ELT flows using REST API
- https://www.crowdstrike.com/wp-content/uploads/2021/06/CrowdStrike-Falcon-Device-Technical-Add-On-Guide.pdf - Shows
  OAuth2 endpoint & scope usage

## Contextual Similar Fields

** These do not mean they can be directly joined on each other, these are fields for each category, per product that are
associated with Access Control **

### Common Identity Fields

| Field            | Okta                | Azure AD                         | On-Prem AD                                         | CrowdStrike              |
|------------------|---------------------|----------------------------------|----------------------------------------------------|--------------------------|
| User ID          | `actor.id`          | `conditions.users.includeUsers`  | `distinguishedName \| onPremisesDistinguishedName` | `device.hostname`        |
| Display Name     | `actor.displayName` | `displayName`                    | `displayName`                                      | `device.last_login_user` |
| Group Membership | `target.id`(group)  | `conditions.users.includeGroups` | `memberOf                                          | transitiveMemberOf`      |                          |

### Device/Platform Fields

** The device ID fields in this table _DO NOT_ map to each other, here for your information **

| Field            | Okta              | Azure AD                            | On-Prem AD                                              | CrowdStrike                             |
|------------------|-------------------|-------------------------------------|---------------------------------------------------------|-----------------------------------------|
| Device ID        | `device.id`       | `conditions.devices.includeDevices` | `computerObjectDN`                                      | `device.device_id`                      |
| Platform/OS      | `client.userAgent | device.os_platform                  | os_version`                                             | `conditions.platforms.includePlatforms` | `operatingSystem`  | `device.platform_id \| os_version` |
| Compliance State | `outcome.result`  | `deviceStates`                      | `device.complianceExpirationDateTime \| complianceState |                                         |
| Last User Logon  |                   |                                     |                                                         | 'device.last_login_user_sid`            |

### Network/Location Fields

| Field               | Okta                         | Azure AD               | On-Prem AD         | CrowdStrike          |
|---------------------|------------------------------|------------------------|--------------------|----------------------|
| IP Address          | `client.ipAddress`           | `conditions.locations` | `logonWorkstation` | `network.local_ip`   |
| Geographic Location | `client.geographicalContext` | `namedLocations`       | N/A                |                      |
| Network Zone        | `request.ipChain`            | `conditions.locations` | `siteName`         | `device.external_ip` |

### Application/Resource Fields

| Field          | Okta             | Azure AD                                      | On-Prem AD             | CrowdStrike          |
|----------------|------------------|-----------------------------------------------|------------------------|----------------------|
| Application ID | `target.id`(app) | `conditions.applications.includeApplications` | `servicePrincipalName` | `process.executable` |
| Resource Type  | `target.type`    | `resourceApplications`                        | `objectClass`          | `file.name`          |

### Policy Control Fields

| Field            | Okta                | Azure AD                        | On-Prem AD                | CrowdStrike           |
|------------------|---------------------|---------------------------------|---------------------------|-----------------------|
| Action/Result    | `outcome.result`    | `grantControls.builtInControls` | `gpcFunctionalityVersion` | `actions.block`?      |
| MFA Requirement  | Event type analysis | `grantControls.builtInControls` | N/A                       | N/A                   |
| Session Controls | N/A                 | `sessionControls`               | `logonHours`              | `actions.quarantine`? |

### Authentication

Okta Events: These are events

- app.OAuth2
   - app.oauth2.as.consent.*
      - app.oauth2.admin.consent.grant/revoke
   - app.oauth2.token.*
   - app.oauth2.as.authorize.*
      - app.oauth2.as.authorize.scope_denied
- access.request.*
- pam.auth_token.*
- device.token.*
- application.provision.group_membership.*
- application.policy.sign_on.*
- user.authentication.auth.*

## Recommended Join/Match Fields

For cross-platform correlation, these fields provide the best matching capabilities:

1. Primary Keys:
   * User identifiers (email/UPN/distinguished name)
   * Device identifiers (MAC address, hardware ID, device name)
   * IP addresses and network identifiers
2. Contextual Matching:
   * Timestamp correlation for event sequences
   * Geographic location matching
   * Application/resource access patterns
3. Risk Assessment Fields:
   * Authentication success/failure patterns
   * Device compliance states
   * Network location anomalies

This schema mapping enables comprehensive conditional access policy analysis across all four platforms, allowing for
unified security posture assessment and cross-platform policy correlation.

## Key Differences Summary

WIP

### Azure AD (Entra ID) + Intune:

* Windows devices provide extensive telemetry through Microsoft Graph APIs
* Linux devices use the same APIs but with significantly fewer populated fields
* Both platforms benefit from cloud based identity and compliance management
* Realtime device status and remote management capabilities

### On-Premises Active Directory:

* Windows devices have basic computer object properties and Group Policy management
* Linux devices have minimal integration, primarily for authentication
* Limited hardware inventory and no built-in compliance monitoring
* Requires additional tools for comprehensive device management

### Data Collection:

* Cloud (Intune): Rich hardware inventory, security posture, and application data
* On-Premises (AD): Basic identity and authentication data only
* Linux Support: Better in cloud scenarios but still limited compared to Windows

| #  | Context Signal           | Okta field                                     | Entra field                             | CrowdStrike field                      | AD attribute                        |
|----|--------------------------|------------------------------------------------|-----------------------------------------|----------------------------------------|-------------------------------------|
| 1  | User GUID / UPN          | people.users.*1                                | users.includeUsers[]3                   | user_attributes.*                      | objectGUID, userPrincipalName       |
| 2  | Group GUID               | people.groups.*                                | users.includeGroups[]                   | user_attributes.groups[]               | memberOf                            |
| 3  | Role / Privilege         | — (Okta uses groups)                           | users.includeRoles[]                    | privileged_access.*                    | adminCount, custom                  |
| 4  | Device ID                | device.registered (true) + device.platform     | devices.deviceFilter.rule               | device_attributes.*                    | deviceId (AAD-hybrid) / computer DN |
| 5  | Managed / Compliant flag | device.managed                                 | builtInControls.compliantDevice (grant) | device_attributes.compliant            | Intune/AAD join metadata            |
| 6  | Client-App Type          | conditions.network.connection (browser vs API) | clientAppTypes[]                        | n/a (CrowdStrike focuses on auth flow) | —                                   |
| 7  | Location / IP            | conditions.network.zone                        | locations.includeLocations[]            | authentication_context.source_ip       | AD FS claim (c:[Type==\"c-ip\"])    |
| 8  | Risk Level               | risk.level (LOW/MED/HIGH)                      | signInRiskLevels[], userRiskLevels[]    | risk_score.threshold (0-10)            | n/a                                 |
| 9  | MFA requirement          | actions.signon.requireFactor                   | grantControls.builtInControls[\"mfa\"]  | mfa_requirement.required               | enforced by ADFS claim              |
| 10 | Session lifetime         | actions.signon.session.maxSession*             | sessionControls.signInFrequency.*       | session_controls.duration_limit        | Kerberos TGT lifetime GP            |

