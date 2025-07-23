**Contents:**
<!-- TOC -->
* [Entra & On-Premises & Intune BloodHound Joins](#entra-on-premises-intune-bloodhound-joins)
* [Bloodhound & Collector](#bloodhound-collector)
    * [Considerations](#considerations)
  * [Sources](#sources)
<!-- TOC -->

# Entra & On-Premises & Intune BloodHound Joins

The purpose of this is to determine which fields for Azure Entra ID and Azure Intune both using Graph API, and
On-Premises Active Directory, that AzureHound, SharpHound, and BloodHound.py are able to retrieve from the three
products Entra, On-Premises AD, and Intune.

# Bloodhound & Collector

This is a comparative table of AzureHound, SharpHound, and BloodHound.py, showing resource types and
fields they can collect from Azure Entra ID (formerly Azure AD), Azure Intune (via Graph API), and on-premises Active
Directory. The table highlights shared, unique, or context-normalized fields. The cells indicate support and field
overlap contextually on the fields, not just by appearance or datatype.


| \#      | Collector             | Data Source\& Resource                     | Key Fields Collected                                                                                                                                                                                         | Shared Field With                                                                                                                                                                                   | Notes on Joins\& Overlap                                                                                                                                                                                                                     |
|:--------|:----------------------|:-------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [1](#1) | **AzureHound**        | Azure Entra ID / AzureAD                   | userPrincipalName, objectId, displayName, mail, accountEnabled, roles, groups, deviceId, deviceDisplayName, deviceTrustType, deviceOperatingSystem, deviceOSType, applications, servicePrincipalId, tenantId | SharpHound (for mail, displayName, userPrincipalName, groups when synchronized/hybrid); BloodHound.py (objectId, displayName with custom parsing)                                                   | Some fields (e.g., userPrincipalName, displayName) may have 1:1 overlap across hybrid identities, but objectId is unique to Entra; deviceId can overlap with on-prem when hybrid joined, but not guaranteed without Intune or sync present.  |
| [2](#2) | **AzureHound**        | Azure Intune                               | deviceId, deviceName, compliant, operatingSystem, userPrincipalName, enrolledDateTime, managedDeviceId, deviceCategory                                                                                       | Entra (deviceId, userPrincipalName), partially with SharpHound/BloodHound.py if hybrid/AAD-joined and Intune is integrated;**Intune deviceId** is often a GUID different from on-prem objectGUID    | deviceId and userPrincipalName may overlap with Entra and on-prem AD**if** co-management/enrollment is synchronized and configured. Compliance status (`isCompliant`) is Intune-specific, but Intune deviceId sometimes replicates in Entra. |
| [3](#3) | **AzureHound**        | AzureRM (ARM Resources)                    | resourceId, resourceGroup, subscriptionId, managementGroupId, keyVaultId, virtualMachineId                                                                                                                   | Limited overlap with on-prem (via synced hostnames or managed identities);**virtualMachineId** may relate to on-prem computerName if hybrid-joined                                                  | ARM resource fields are unique unless hybrid configurations specifically set correlating names/IDs. Hostname can sometimes allow normalization.                                                                                              |
| [4](#4) | **AzureHound**        | Azure Apps\& Service Principals            | appId, displayName, servicePrincipalId, publisher, owners, permissions                                                                                                                                       | No direct analog in on-prem AD, but displayName may show synchronization in naming conventions                                                                                                      | AppId/servicePrincipalId are Azure-only; displayName may overlap intentionally (but does not mean referential identity).                                                                                                                     |
| [5](#5) | **SharpHound**        | On-Premises AD                             | sAMAccountName, distinguishedName, objectGUID, objectSid, memberOf, logonScript, homeDirectory, userPrincipalName, givenName, sn, description                                                                | Overlap: userPrincipalName (if hybrid/AAD Connect present), givenName, sn, description with Azure Entra; objectGUID is on-prem only, except with device join/via msDS-CloudExtensionAttribute links | **objectGUID** and **objectSid** are unique to on-prem unless hybrid config synchronizes (not 1:1 for most cloud-joined objects); memberOf/group overlap where group syncs exist.                                                            |
| [6](#6) | **SharpHound**        | On-Premises AD (Computers)                 | dNSHostName, operatingSystem, lastLogonTimestamp, objectGUID                                                                                                                                                 | AzureHound (for deviceName, operatingSystem if hybrid-joined/Azure-registered)                                                                                                                      | Hostname/operatingSystem overlap possible only in hybrid setups; objectGUID is local only.                                                                                                                                                   |
| [7](#7) | **SharpHound**        | On-Premises AD (Groups, GPOs, OUs, Trusts) | groupName, distinguishedName, objectSid, gPLink, gPOptions, OU name, trustType                                                                                                                               | None directly, except groupName if group is cloud-synced to Entra; trustType, gPOptions are AD-only                                                                                                 | GPOs/OUs/trusts are not surfaced in Azure Entra/Intune; groupName may duplicate in both domains (hybrid identity), but SIDs will never overlap.                                                                                              |
| [8](#8) | **BloodHound.py**     | On-Premises AD                             | sAMAccountName, userPrincipalName, memberOf, distinguishedName, objectSid, objectGUID, machine name, servicePrincipalName                                                                                    | Same as SharpHound for AD fields; overlap with AzureHound for userPrincipalName, displayName only if hybrid identity is present                                                                     | Collects a subset of what SharpHound sees; differences may appear in how fields are parsed but overlap for typical user/computer accounts.                                                                                                   |
| [9](#9) | **All (when hybrid)** | All sources                                | userPrincipalName, displayName, mail, deviceName/hostname, operatingSystem                                                                                                                                   | All                                                                                                                                                                                                 | Overlap present**only** in hybrid, co-managed identity/device join scenarios (usually Entra/Intune \& on-prem AD synchronized).                                                                                                              |


### Considerations

- **Field Overlap**: Only fields that have *both* semantic and referential overlap (not just similar values or formats)
  are considered “shared.” For hybrids, fields like userPrincipalName, displayName, and deviceName can/should match;
  IDs (objectId, objectGUID) usually do not.
- **Unique Fields**: Fields like Intune managedDeviceId, GPO fields, Azure resourceGroup, subscriptionId, etc., are
  *unique* to each data source (Entra, AD, Intune), even if their datatype
  appears similar.
- **Join Requirements**: Actual joinability depends on configuration: identity hybrid mode, device sync, UPN suffix
  match, and intentional attribute flow.

If you need a markedly detailed field-by-field schema mapping for each collector across these products, or a list of the
exact JSON schema for import into BloodHound GUI, refer to the AzureHound/SharpHound schema files and their source code
documentation directly for the most granular, up-to-date field listings as referenced above.

BloodHound.py repository: https://github.com/dirkjanm/BloodHound.py

## Sources

- [1](https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html) (AzureHound resource types and
  example fields: users, devices, roles, groups, apps, service principals)
- [1](https://bloodhound.specterops.io/collect-data/ce-collection/azurehound) (AzureHound collector workflow, supported
  authentication, and output structure; details on Entra and deviceId fields)
- [1](https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound-all-flags.html) (AzureHound all supported
  collection flags, object types including users, devices, resource groups, management-groups; field types explained)
- [2](https://academy.hackthebox.com/course/preview/active-directory-bloodhound) (BloodHound/SharpHound—what objects
  and fields are collected from on-prem AD and how data relates to Azure when hybrid present)
- [4](https://bloodhound.readthedocs.io/en/latest/) (BloodHound documentation—high-level field and schema overview,
  including legacy Azure support)
- [5](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html) (SharpHound parameters, collection
  options, and output file types and schemas)
- [6](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-enumerate/) (AD enumeration standard
  fields—filling in specific object property overlaps like objectGUID vs. objectSid vs. userPrincipalName)
- [8](https://pkg.go.dev/github.com/certmichelin/azurehound/v3/constants) (AzureHound code-level resource names and IDs
  for AzureRM, AzureAD)
- [10](https://github.com/dirkjanm/BloodHound.py) (BloodHound.py—repo and code showing which fields and types are
  collected compared to SharpHound; supports same base schema for queries)
- [3](https://learn.microsoft.com/en-us/answers/questions/1433217/how-to-enroll-existing-microsoft-entra-id-joined-d) (
  Hybrid device join/enrollment details for Azure Entra, Intune, field overlaps, and where deviceId, userPrincipalName
  syncs may occur)
- [12](https://learn.microsoft.com/en-us/answers/questions/953546/azure-ad-shows-device-compliance-as-na-while-intun) (
  Intune compliance property overlap—when Intune and Entra device objects are referenced by deviceId / compliance—shows
  where values cannot simply be mapped without context)

[1]: https://bloodhound.specterops.io/collect-data/ce-collection/azurehound
[2]: https://academy.hackthebox.com/course/preview/active-directory-bloodhound
[3]: https://learn.microsoft.com/en-us/answers/questions/1433217/how-to-enroll-existing-microsoft-entra-id-joined-d
[4]: https://bloodhound.readthedocs.io/en/latest/
[5]: https://bloodhound.specterops.io/install-data-collector/install-azurehound/azure-configuration
[6]: https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-enumerate/
[7]: https://docs.datadoghq.com/security/default_rules/def-000-85j/
[8]: https://pkg.go.dev/github.com/certmichelin/azurehound/v3/constants
[9]: https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound.html
[10]: https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html
[11]: https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound-all-flags.html
[12]: https://learn.microsoft.com/en-us/answers/questions/953546/azure-ad-shows-device-compliance-as-na-while-intun
[13]: https://docs.azure.cn/en-us/entra/identity/devices/manage-device-identities
[14]: https://pkg.go.dev/github.com/bloodhoundad/azurehound/v2
[15]: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
[16]: https://docs.axonius.com/docs/microsoft-azure-active-directory-ad
