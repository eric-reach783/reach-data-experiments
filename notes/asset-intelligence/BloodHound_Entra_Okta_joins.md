# Cross-Platform Field Correlations

**Contents:**
<!-- TOC -->

* [Cross-Platform Field Correlation: Azure Entra ID, Okta System Log, BloodHound REST API \& AzureHound](#cross-platform-field-correlation-azure-entra-id-okta-system-log-bloodhound-rest-api-azurehound)
  * [Sources](#sources)
    * [Row 1: users.id / actor.id / objectId (User)](#row-1-usersid-actorid-objectid-user)
    * [Row 2: users.displayName / actor.displayName / displayName](#row-2-usersdisplayname-actordisplayname-displayname)
    * [Row 3: users.userPrincipalName / actor.alternateId / mail/userPrincipalName](#row-3-usersuserprincipalname-actoralternateid-mailuserprincipalname)
    * [Row 4: groups.id / target.id / objectId (Group)](#row-4-groupsid-targetid-objectid-group)
    * [Row 5: groups.displayName / target.displayName / displayName](#row-5-groupsdisplayname-targetdisplayname-displayname)
    * [Row 6: devices.id / client.device / objectId (Computer)](#row-6-devicesid-clientdevice-objectid-computer)
    * [Row 7: signInLogs.ipAddress / client.ipAddress](#row-7-signinlogsipaddress-clientipaddress)
    * [Row 8: users.accountEnabled / result (SUCCESS/FAILURE) / enabled (User)](#row-8-usersaccountenabled-result-successfailure-enabled-user)
<!-- TOC -->

# Azure Entra ID, Okta System Log, BloodHound REST API \& AzureHound Collector

Below is a correlation matrix showing fields that are _should be_ available across Microsoft Entra ID (Azure AD), Okta 
System Logs, BloodHound REST API/Ciphers, and the AzureHound collector. Each row lists sources for each matching 
field or schema, for joinability, context, and APIs path for quick reference.

| \# | Azure Entra Field       | Azure Entra Fields API              | Okta Field                | Okta Fields API           | BloodHound Field          | BloodHound Fields API    | AzureHound Field       | AzureHound Fields API   | AzureHound Field Type | Azure Entra Field Type | Okta Field Type | BloodHound Field Type | Direct Join | Composite Join         | Transforms Direct                    | Transforms Composite                                                                      | Context                                                                                 |
|:---|:------------------------|:------------------------------------|:--------------------------|:--------------------------|:--------------------------|:-------------------------|:-----------------------|:------------------------|:----------------------|:-----------------------|:----------------|:----------------------|:------------|:-----------------------|:-------------------------------------|:------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------|
| 1  | users.id                | /users/{id}                         | actor.id                  | /api/v1/logs (System Log) | props.objectid (User)     | /api/v2/base/{object_id} | objectId (User)        | collector output (JSON) | string GUID           | string GUID            | string hex      | string SID            | false       | true                   | n/a                                  | Okta`actor.alternateId` → Entra `userPrincipalName`, then to BH `objectSid` via directory | Directory object IDs differ per system; correlation bridges via user principal/email[3] |
| 2  | users.displayName       | /users?select=displayName           | actor.displayName         | /api/v1/logs              | props.displayname (User)  | /api/v2/base/{id}        | displayName            | collector output(JSON)  | string                | string                 | string          | string                | true        | true                   | Trim whitespace                      | If duplicate, disambiguate via tenant or unique attribute                                 | Human-readable label, propagates between directories and logs[4]                        |
| 3  | users.userPrincipalName | /users?select=userPrincipalName     | actor.alternateId (email) | /api/v1/logs              | props.email               | user JSON                | mail/userPrincipalName | collector output (JSON) | string UPN            | string UPN             | string email    | string email          | true        | true                   | Lowercase, normalize guest indicator | Map Okta alternateId to Entra UPN for federation                                          | SSO/federation flows use these fields for identity[4]                                   |
| 4  | groups.id               | /groups/{id}                        | target.id (group)         | /api/v1/logs              | props.objectid (Group)    | /api/v2/base/{id}        | objectId (Group)       | collector output (JSON) | string GUID           | string GUID            | string          | string SID            | false       | true                   | None                                 | Okta group → Azure group via Graph membership, then to SID                                | Group identifiers tie to specific platform container[7]                                 |
| 5  | groups.displayName      | /groups?select=displayName          | target.displayName        | /api/v1/logs              | name (Group)              | /api/v2/base/{id}        | displayName            | collector output (JSON) | string                | string                 | string          | string                | true        | true                   | Trim/case-fold                       | Pair with tenant to split duplicates                                                      | Admin interfaces use for group display mapping[4]                                       |
| 6  | devices.id              | /devices/{id}                       | client.device (hash)      | /api/v1/logs              | props.objectid (Computer) | /api/v2/base/{id}        | objectId (Device)      | collector output (JSON) | string GUID           | string GUID            | string          | string SID            | false       | true                   | n/a                                  | Map Azure`deviceId` ↔ Okta `device.uuid` via integration                                  | Device registration IDs matched via inventory synchronization[7]                        |
| 7  | signInLogs.ipAddress    | /auditLogs/signIns?select=ipAddress | client.ipAddress          | /api/v1/logs              | n/a                       | n/a                      | n/a                    | n/a                     | string IP             | IPv4/6                 | IPv4/6          | n/a                   | false       | true (if present in 2) | CIDR normalization                   | Join on session event                                                                     | IP address occurs in logs for session tracing[8]                                        |
| 8  | users.accountEnabled    | /users?select=accountEnabled        | result (SUCCESS/FAILURE)  | /api/v1/logs              | n/a                       | n/a                      | enabled (User)         | collector output (JSON) | boolean               | boolean                | string enum     | boolean               | false       | true                   | Okta result to boolean               | Combine Okta + Entra fields for active/inactive logic                                     | Account state affects access eligibility[4]                                             |

## Sources

### Row 1: users.id / actor.id / objectId (User)

- [9](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)
- [2](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/)
- [3](https://bloodhound.readthedocs.io/en/latest/further-reading/json.html)

### Row 2: users.displayName / actor.displayName / displayName

- [1](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)
- [3](https://bloodhound.readthedocs.io/en/latest/further-reading/json.html)
- [4](https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html)

### Row 3: users.userPrincipalName / actor.alternateId / mail/userPrincipalName

- [1](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)
- [5](https://developer.okta.com/docs/reference/system-log-query/)
- [4](https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html)

### Row 4: groups.id / target.id / objectId (Group)

- [6](https://learn.microsoft.com/en-us/graph/azuread-users-concept-overview)
- [2](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/)
- [7](https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound-all-flags.html)

### Row 5: groups.displayName / target.displayName / displayName

- [1](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)
- [2](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/)
- [4](https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html)

### Row 6: devices.id / client.device / objectId (Computer)

- [6](https://learn.microsoft.com/en-us/graph/azuread-users-concept-overview)
- [2](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/)
- [7](https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound-all-flags.html)

### Row 7: signInLogs.ipAddress / client.ipAddress

- [6](https://learn.microsoft.com/en-us/graph/azuread-users-concept-overview)
- [5](https://developer.okta.com/docs/reference/system-log-query/)
- [8](https://cloud.google.com/chronicle/docs/ingestion/default-parsers/okta)

### Row 8: users.accountEnabled / result (SUCCESS/FAILURE) / enabled (User)

- [1](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)
- [5](https://developer.okta.com/docs/reference/system-log-query/)
- [4](https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html)


[1]: https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0

[2]: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/

[3]: https://bloodhound.readthedocs.io/en/latest/further-reading/json.html

[4]: https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html

[5]: https://developer.okta.com/docs/reference/system-log-query/

[6]: https://learn.microsoft.com/en-us/graph/azuread-users-concept-overview

[7]: https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound-all-flags.html

[8]: https://cloud.google.com/chronicle/docs/ingestion/default-parsers/okta

[9]: https://link.springer.com/10.1007/s11761-022-00353-5

[10]: https://www.scitepress.org/DigitalLibrary/Link.aspx?doi=10.5220/0012735700003690

[11]: https://academic.oup.com/bioinformatics/article/doi/10.1093/bioinformatics/btad080/7033465

[12]: https://ieeexplore.ieee.org/document/9671423/

[13]: https://dl.acm.org/doi/10.1145/3390557.3394128

[14]: https://dl.acm.org/doi/10.1145/3580305.3599465

[15]: https://ieeexplore.ieee.org/document/10872705/

[16]: https://www.semanticscholar.org/paper/61a272d521126b7eb4cba1ba045f3ec288db7c6a

[17]: https://academic.oup.com/nar/article/53/W1/W84/8129374

[18]: https://biss.pensoft.net/article/110724/

[19]: https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-user?view=graph-rest-beta

[20]: https://learn.microsoft.com/en-us/graph/use-the-api

[21]: https://learn.microsoft.com/en-us/graph/api/resources/useraccountinformation?view=graph-rest-beta

[22]: https://learn.microsoft.com/en-us/graph/permissions-reference

[23]: https://github.com/SpecterOps/BloodHound-Legacy/blob/master/docs/data-collection/azurehound-all-flags.rst

[24]: https://stackoverflow.com/questions/48229949/get-all-user-properties-from-microsoft-graph

[25]: https://stackoverflow.com/questions/29016001/obtaining-system-log-using-okta-api

[26]: https://hexdocs.pm/bloodhound/Bloodhound.Client.html

[27]: https://github.com/SpecterOps/AzureHound

[28]: https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0

[29]: https://bloodhound.specterops.io/integrations/bloodhound-api/json-formats

[30]: https://infosecwriteups.com/securing-azure-hunting-with-azurehound-d7ebb58e0fde

[31]: https://arxiv.org/pdf/2205.01833.pdf

[32]: https://arxiv.org/pdf/2309.13610.pdf

[33]: https://arxiv.org/pdf/2411.09999v1.pdf

[34]: https://dl.acm.org/doi/pdf/10.1145/3639478.3643080

[35]: https://arxiv.org/pdf/2402.07540.pdf

[36]: https://arxiv.org/pdf/2304.11116.pdf

[37]: https://arxiv.org/html/2501.08947

[38]: https://arxiv.org/pdf/2110.12996.pdf

[39]: https://arxiv.org/html/2501.00309v1

[40]: https://arxiv.org/pdf/2303.13948v1.pdf
