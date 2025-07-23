# Device Data in Azure AD (Entra ID) vs On-Prem AD for Windows and Linux

- Entra: formerly Azure AD, provides cloud-based identity and access management (IAM) for users, devices, and apps including authentication passwordless and multi‑factor, single sign-on (SSO), conditional access, privileged identity management, and identity protection.
- Intune: Formely Endpoint Manager, is a cloud-based unified endpoint management (UEM) for devices (Windows, macOS, iOS, Android, Linux, etc.) which provides device enrollment, configuration and compliance policies, software/app distribution, OS updates, remote tasks (e.g., wipe, malware scan) capabilities.

## Entra ID (Azure AD) with Intune – Windows vs. Linux Devices

<details>

In an **Azure AD + Intune** environment, all managed devices (Windows, Linux, etc.) can be queried via Microsoft Graph.
However, the **available data and schema differ by platform**:

* **Microsoft Graph Intune API (Beta)** – Provides detailed device information through the `windowsManagedDevice` resource type. This Beta endpoint covers all Intune-managed devices, not just Windows. For example, `GET /beta/deviceManagement/managedDevices` returns a collection of `windowsManagedDevice` objects (inheriting from `managedDevice`). Windows devices have rich properties, while Linux devices have fewer populated fields. The `deviceType` property indicates platform (`windows`, `mac`, `android`, `linux`). Intune’s Beta API can list Linux endpoints, but many Windows-specific fields are empty or not applicable.
* **Microsoft Graph Intune API (v1.0)** – The stable endpoint (`GET /v1.0/deviceManagement/managedDevices`) returns all Intune-managed devices with a limited schema. Certain detailed properties available in beta (e.g., `hardwareInformation`, Windows-specific security state) are absent in v1.0. Both Windows and Linux devices are included, but data on Linux endpoints is minimal (e.g., device name, OS, compliance state). Intune’s Linux support is new, so hardware or security fields are often null for Linux machines. (By default, many hardware info sub-fields are null until explicitly retrieved, and some may not apply to Linux.)
* **Data Collected / Schema Differences** – Windows Intune clients report extensive information, including hardware specs, OS version, compliance state, encryption status, and antivirus status. The beta schema’s `hardwareInformation` object includes storage, serial number, TPM info, battery levels, and more, relevant to Windows and macOS. In contrast, Linux Intune clients report a smaller subset of information. Intune marks Linux devices as “corporate-owned” and evaluates compliance, but lacks detailed hardware inventory or Windows-specific fields like BitLocker, Defender, or IMEI. The Intune device summary confirms separate counting of Linux devices, indicating limited support.
* **Beta Endpoint and Linux** – The beta endpoint is not limited to Windows. It returns Linux devices enrolled in Intune as well. You use the same endpoints for all platforms. For example, a Linux Ubuntu Intune device appears in the `managedDevices` list with `operatingSystem: “Ubuntu 22.04”` and `deviceType: “linux”`. The data for Linux is sparser. (Intune Linux agent doesn’t collect all hardware details yet.)
* **Azure AD Device Records** – In Azure AD (Entra ID), each Intune-enrolled device has a directory object (`GET /devices` in Graph) that stores identity-centric info like OS type and version, join type, compliance, and management flags. This diverges between Windows and Linux:

  * A **Windows 10/11 PC** can be **Azure AD Joined** (cloud-joined, allowing user sign-in with Entra credentials) or
    **Hybrid AD Joined** (on-prem AD joined and Azure AD registered via sync). Azure AD denotes this with `trustType`
    values: e.g. `AzureAd` for cloud-joined, or `ServerAd` for on-prem domain joined. Such devices typically show *
    *`isManaged: true` and `isCompliant: true/false`** if managed by Intune. They have Azure AD info and can be
    targeted by conditional access or device-based authentication.
  * An **Intune-enrolled Linux** device **cannot do a full Azure AD Join** – Azure AD currently **supports only
    registration** for Linux endpoints. When a Linux machine (Ubuntu/RHEL desktop) enrolls via the Intune Linux
    client, it registers in Azure AD as a **“Workplace” joined device** (Azure AD registered, similar to mobile BYOD).
    In Azure AD Graph, its `trustType` will be `"Workplace"` (meaning Azure AD registered) rather than `AzureAd`. In
    effect, the Linux device object is created by the **Device Registration Service via Intune**, so it shows up in
    the directory’s “All Devices” with an OS and owner but *not* as an AD-joined computer.

### Key Graph API Endpoints (Cloud/Entra)

The table below outlines relevant Graph API endpoints and how they apply to Windows vs. Linux devices in Azure
AD/Intune:

- **GET** `/beta/deviceManagement/managedDevices` - Intune Beta, list all Intune-managed devices (returns `windowsManagedDevice` objects with full detail). Includes device name, user, OS, compliance state, and deep hardware/software info in beta. Returns*all* platforms enrolled in Intune (Windows, Linux, macOS, iOS, etc). **Windows:** Rich schema (e.g. `hardwareInformation`, `ownerType`, `managementState`). **Linux:** Included in results but many Windows-specific fields will be blank or default.
- GET `/v1.0/deviceManagement/managedDevices` - Intune v1.0 lists managed devices with a stable (limited) schema. It includes core properties like device ID, name, OS, ownership, compliance, and last check-in. By default, it doesn’t include verbose hardware info. It supports all Intune-managed devices, including Windows and Linux.
- For Windows devices, it displays basic fields like OS, compliance, and lastSync. For Linux devices, it displays similar fields, with the OS reflecting the device’s operating system and compliance state from Intune.
- **GET** `/v1.0/deviceManagement/managedDevices` - Azure AD Devices - List registered or joined devices in a directory. Each device’s info includes display name, Azure AD object ID, OS type/version, device ownership, compliance status, management status, and join type.

  **Windows:** Listed if joined or registered to Azure AD. Key fields: trustType (Azure AD, Server Ad, or Workplace), OS version, and OS name.

  **Linux:** Listed only if Intune-enrolled (Azure AD registration for Linux is via Intune). Entries typically have trustType: Workplace and OS like “Ubuntu 22.04”. They show isManaged: true and compliance state from Intune, but Azure AD lacks Windows-specific info (e.g., group policy).

**NOTE:**

Both services have an "ID" attribute to uniquely identify objects. The Azure AD ID field refers to the object ID, while
the Intune ID field is the Intune device ID.

Intune never directly references the Azure AD device object. Any modifications in the Endpoint Manager admin
center are replicated from Intune managedDevice to the Azure AD device object. Changes made in Azure AD are similarly
replicated back to Intune to keep the two records in sync.

The Intune managedDevice object's AzureADDeviceId attribute is a reference to the Azure AD device object's ID attribute.
Intune-managed devices have both Azure AD and Intune device records. User objects exist only in Azure AD and are
referenced from Intune.

When a device is enrolled in Intune, it registers two objects in Microsoft Graph:

- One under /deviceManagement/managedDevices/{managedDeviceId} (Intune managedDevice)
- Another under /devices/{deviceId} (Azure AD device object)
  The azureADDeviceId in the first object links directly to the deviceId (the Object ID) in the second

#### API: Beta vs. 1.0 with Delta

* v1.0 - **production-ready**, stable, minimal default responses
* Beta - **preview**, experimental features and endpoints, richer schemas.
  * returns more fields without the need for `$select`
* Delta - **mechanism** for tracking incremental changes to various resource collections.

Ex:

```plaintext
GET https://graph.microsoft.com/v1.0/users/delta

These two API calls return similar data
GET https://graph.microsoft.com/beta/me == GET https://graph.microsoft.com/v1.0/me?$select=displayName,mail,streetAddress
```

Currently we use the beta API in these connector files:

- https://github.com/search?q=repo%3AReach-Security%2Freach_security%20path%3A%22ms_graph_api.py%22%20%22beta%2F%22&type=code

#### Sources:

- https://techcommunity.microsoft.com/blog/intunecustomersuccess/understanding-the-intune-device-object-and-user-principal-name/3657593
- https://learn.microsoft.com/en-us/graph/delta-query-overview

</details>

## On-Premises Active Directory (On-Prem AD) – Windows vs. Linux Devices

<details>

For a purely on-premises AD environment (without Entra ID or Intune), it differs. The directory must be queried using traditional methods (LDAP or PowerShell) since there’s no Microsoft Graph API for on-prem AD. On-prem AD device data is also queried using traditional methods.
limited compared to Intune’s data. Key points:

* **AD Computer Object Attributes:** When a Windows machine joins an Active Directory domain, the domain controller
  records a computer object with basic attributes. AD stores the operating system name and version (as strings) and
  updates metadata like the last logon time. For example, a Windows 11 domain-joined PC’s AD object might have
  `OperatingSystem = “Windows 11 Enterprise”` and `OperatingSystemVersion = “10.0 (22000)”`. These fields are set
  automatically by the domain join process for Windows. Linux systems can be domain-joined using solutions like
  Samba/SSSD, but AD doesn’t natively recognize or update their OS attributes. Often, if you join an Ubuntu or RHEL
  server to AD, the `OperatingSystem` field is either a generic placeholder or blank unless manually updated.
  AD doesn’t collect hardware details or compliance info; it’s just a directory entry.
* **No Intune/MDM Data:** On-prem AD alone doesn’t track device compliance, encryption, or hardware inventory. It lacks
  concepts like “MDM managed” or “compliant,” which are cloud-based (Intune). AD devices are essentially security
  principals (with a GUID, name, and descriptive fields). Organizations rely on on-prem management tools for additional
  data.
* **Retrieving Device Info (On-Prem):** Since Graph API is not available for on-prem AD, you must query AD directly:

  * *LDAP or PowerShell:* An admin can use PowerShell Active Directory cmdlets or LDAP queries to retrieve computer
    objects. For instance, `Get-ADComputer -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate` lists
    these fields. This works for Windows devices (with meaningful values) and Linux devices (with blank or custom
    values). For example, pre-staged Linux computer accounts have blank OS fields in AD, requiring
    a PowerShell script, or manual entry to fill in the OS name/version after joining. This manual step is automatic
    for Windows but not for Linux.
  * *WMI/Remote Queries:* To gather detailed hardware or software data in an on-prem network, an admin would query
    each machine directly (e.g. using WMI or SSH). For instance, using PowerShell’s CIM/WMI classes (like
    `Get-CimInstance Win32_ComputerSystem` on each Windows PC) can retrieve serial numbers, BIOS info, etc., but this
    is a custom solution. **There is no out-of-the-box AD mechanism to centralize this data** – typically one would
    use **System Center Configuration Manager (SCCM)** or similar. SCCM (if deployed) install an agent on each client
    to collect hardware/software inventory and stores it in a SQL database. SCCM has its own APIs or PowerShell module
    to extract this info. Recent versions of SCCM no longer support direct Linux client management.
    managing Linux in an on-prem setup might require third-party tools.
  *
* **Comparing On-Prem to Entra ID/Intune:** An on-prem AD environment is less uniform for device data. Windows devices
  in AD authenticate and update their OS info, while Linux devices are often just entries for Kerberos/LDAP
  authentication. Cloud Intune offers more data and management.

  * Intune/Graph can determine if a Windows device complies with policies or if a device wipe has been issued, but
    on-prem AD lacks this information. Auditing each system manually or via scripts is required.
  * Azure AD/Intune can retrieve real-time hardware details (manufacturer, model, TPM status) for Windows. On-prem AD
    lacks this by default; admins can manually populate the Description field or an extension attribute with some info.
  * **Endpoint queries:** In Azure AD, you use Graph queries to get device info centrally. In on-prem AD, you query
    domain controllers via LDAP. There are endpoints like AD Web Services (used by PowerShell), but not a REST API.
    On-prem endpoints are domain controllers responding to LDAP/Kerberos, and data is gathered using AD query tools.

#### MS‑ADTS: Microsoft Active Directory Technical Specification

Offical open specification documentation for the schema, state, and protocol behaviors for Active Directory Domain Services and Lightweight Directory Services

- Active Directory Lightweight Directory Services (AD LDS) - Microsoft’s full-, on-premises directory service
- Active Directory Domain Services (AD DS) - Formerly called ADAM, lightweight, stand-alone LDAP directory service 
  primarily used for application-specific purposes.

Sources:

- https://ldapwiki.com/wiki/Wiki.jsp?page=ObjectGUID
- https://winprotocoldoc.z19.web.core.windows.net/MS-ADLS/%5bMS-ADLS%5d.pdf

</details>

### Approaches to Get Similar Data On-Prem

<details>
These methods exclude the use of BloodHound Collectors.

Since there is no direct Graph API for on-prem AD, here are methods to capture similar information about domain-joined
devices:


| Method/Tool                        | What it Provides                                                                                                                                                                                                                                            | Windows vs. Linux Considerations                                                                                                                                                                                                                                                                                                   | Reference                                                                                                    |
|------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| **AD PowerShell (Get-ADComputer)** | Retrieves AD computer object fields (name, OS, last logon, etc.) from a domain controller. Useful for basic inventory of what OS is recorded in AD and whether the account is enabled.                                                                      | **Windows:** OS info is usually up-to-date (set during domain join) – e.g. a Windows PC will show **OperatingSystem = “Windows 10 Pro”** in AD. **Linux:** OS fields may be missing or generic. Admins might script updates to tag Linux systems with their OS version in AD. No hardware or compliance data is available from AD. | https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2025-ps |
| **LDAP Queries / ADSI**            | Low-level querying of AD via LDAP. Equivalent data to the above – you can read attributes like`operatingSystem` or `operatingSystemVersion` on computer objects. Allows custom filters (e.g. find all computers with `operatingSystem` containing “Linux”). | Same limitations: only as accurate as what’s stored in AD. Typically, Windows machines update their own AD attributes; Linux might not. Also, LDAP can retrieve attributes like last logon timestamps to see active devices.                                                                                                       | Standard AD schema documentation for computer objects                                                        |

In an Azure AD/Entra + Intune environment, you access the Graph APIs, including beta Intune endpoints, which retrieve detailed device information across operating systems. Windows devices provide more comprehensive data than Linux devices due to Intune’s current capabilities.

In contrast, in a traditional on-premises Active Directory (AD) setup, information is fragmented and limited. You can get basic operating system and identity information from AD for domain-joined devices, with Windows being well-documented and Linux being minimal. Anything beyond requires additional tooling or scripts.

On-premises AD lacks a direct beta API equivalent. Administrators must rely on AD queries and management system APIs to gather similar data. Device schemas differ significantly. Intune’s device record includes compliance status, owner type, and hardware specifications, while an AD computer object lacks these features (it functions as an account with an operating system name).

Each method has specific required fields and formats. Examples of Graph API outputs or AD PowerShell results are
provided.

</details>

## Fields

<details>

- On-premises AD contains technical and infrastructure-focused attributes not present in Azure AD/Entra
- Azure AD/Entra includes modern cloud-specific properties for licensing, compliance, and service integration

### Overlapping Attributes

These are attributes that should be able to match directly to each other, as the share the same purpose.

#### Device Objects


| On-Premises AD Attribute                     | Azure AD Attribute                                         | Description       |
|----------------------------------------------|------------------------------------------------------------|-------------------|
| cn, displayName, sn, distinguishedName, name | displayName, registeredOwners, onPremisesDistinguishedName | Device name       |
| **dNSHostName**                              | onPremisesDnsHostName, device.name,devices.hostNames       | DNS hostname      |
| **operatingSystem**                          | operatingSystem                                            | Operating system  |
| **operatingSystemVersion**                   | operatingSystemVersion                                     | OS version        |
| userCertificate, alternativeSecurityIds      | alternativeSecurityIds                                     | Certificate data  |
| **objectGUID** (MS-ADLS/LDAP Display Name)   | deviceId                                                   | Unique identifier |

#### Group Objects


| On-Premises AD Attribute                     | Azure AD Attribute          | Description         |
|----------------------------------------------|-----------------------------|---------------------|
| cn, displayName, sn, distinguishedName, name | displayName                 | Group name          |
| **description**                              | description                 | Group description   |
| **mail**                                     | mail                        | Group email address |
| **mailNickname**                             | mailNickname                | Email alias         |
| **member**                                   | members                     | Group membership    |
| **sAMAccountName**                           | onPremisesSamAccountName    | SAM account name    |
| **proxyAddresses**                           | proxyAddresses              | Email addresses     |
| **groupType**                                | securityEnabled/mailEnabled | Group type flags    |

#### User Objects

#### Domain Objects

### Org objects

### On-Premises Unique Attributes

### Azure/Entra Unique Attributes

#### Section Specific Source:

- https://activedirectorypro.com/ad-ldap-field-mapping/
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adls/71ffde4b-5b5b-4623-9f40-cf4c835ceaa2
- https://www.rfc-editor.org/rfc/pdfrfc/rfc2849.txt.pdf
- https://winprotocoldoc.z19.web.core.windows.net/MS-ADLS/%5bMS-ADLS%5d.pdf
- https://agbo.blog/2020/12/09/rename-ad-user-using-powershell/
- https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-deviceenrollmenttype?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/migrate-azure-ad-graph-property-differences
- https://learn.microsoft.com/vi-vn/graph/api/resources/device?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/concept-attributes
- https://learn.microsoft.com/en-us/graph/api/resources/windowsupdates-azureaddevice?view=graph-rest-beta
- https://learn.microsoft.com/en-us/graph/api/windowsupdates-azureaddevice-get?view=graph-rest-beta&tabs=http
- https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-beta
-

</details>

## General Sources:

<details>

- Microsoft Graph Beta – Intune `windowsManagedDevice` resource and schema

  - [Intune devices – windowsManagedDevice (beta) | Microsoft Learn](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-windowsmanageddevice?view=graph-rest-beta)
  - Cloud/Entra: Device data, schema, endpoint, Windows/Linux supported fields, schema differences
- Microsoft Graph Beta – Example of deviceType in managedDevices

  - [List managedDevices - Microsoft Graph beta | Microsoft Learn](https://learn.microsoft.com/en-us/graph/api/intune-devices-list-manageddevices?view=graph-rest-beta)
  - Cloud/Entra: Linux deviceType support, endpoint for both Windows and Linux
- Microsoft Graph v1.0 – Intune `managedDevice` resource

  - [managedDevice resource type | Microsoft Graph v1.0](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice?view=graph-rest-1.0)
  - Cloud/Entra: Stable endpoint, basic schema, device inventory fields
- Microsoft Graph v1.0 – List managed devices

  - [List managedDevices - Microsoft Graph v1.0](https://learn.microsoft.com/en-us/graph/api/intune-devices-list-manageddevices?view=graph-rest-1.0)
  - Cloud/Entra: Supported actions, schema, Windows/Linux device listing
- Microsoft Intune – Supported devices and browsers

  - [Supported devices and browsers for Microsoft Intune | Microsoft Learn](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/supported-devices-browsers)
  - Cloud/Entra: Linux device management support, Intune enrollment, OS limitations
- Microsoft Intune – Linux enrollment and management

  - [Enroll Linux devices in Microsoft Intune | Microsoft Learn](https://learn.microsoft.com/en-us/mem/intune/enrollment/linux-enrollment)
  - Cloud/Entra: Linux Intune agent, enrollment process, what data is available
- Microsoft Intune – Linux device compliance policies

  - [Create compliance policies for Linux in Microsoft Intune | Microsoft Learn](https://learn.microsoft.com/en-us/mem/intune/protect/compliance-policy-create-linux)
  - Cloud/Entra: Compliance checks, supported Linux telemetry, compliance state reporting
- Microsoft Docs – Azure AD device registration and join types

  - [Join types in Azure Active Directory | Microsoft Learn](https://learn.microsoft.com/en-us/azure/active-directory/devices/device-registration-overview)
  - Cloud/Entra: Join types (`AzureAd`, `ServerAd`, `Workplace`), Linux vs. Windows directory status
- Microsoft Graph – device resource type (Azure AD/Entra)

  - [device resource type - Microsoft Graph v1.0](https://learn.microsoft.com/en-us/graph/api/resources/device?view=graph-rest-1.0)
  - Cloud/Entra: Directory device object, `trustType`, compliance, management status
- Microsoft Q&A – Linux Azure AD device registration via Intune

  - [Why do I not see my Azure VM in Azure AD devices? | Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/1016565/why-do-i-not-see-my-azure-vm-in-azure-ad-devices)
  - Cloud/Entra: How Linux appears in Entra device list, registration, device object differences
- Microsoft Graph – Device properties: compliance, hardware, and management

  - [windowsManagedDevice resource type - Microsoft Graph beta](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-windowsmanageddevice?view=graph-rest-beta)
  - Cloud/Entra: Full list of properties, hardware and compliance states
- Microsoft Learn – Azure AD device trustType property

  - [Device object properties in Azure Active Directory | Microsoft Learn](https://learn.microsoft.com/en-us/azure/active-directory/devices/device-objects-properties)
  - Cloud/Entra: Property meanings (`trustType`, `isCompliant`, etc.), schema comparison
- Microsoft Docs – AD computer object schema

  - [Computer class - Windows Server | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/adschema/c-computer)
  - On-prem AD: OS and other computer object attributes
- Microsoft Docs – PowerShell AD cmdlets

  - [Get-ADComputer (ActiveDirectory) | Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer)
  - On-prem AD: Querying OS fields, attribute comparison, data retrieval
- Microsoft Learn – SCCM/Linux client management (on-prem)

  - [Support for Linux and UNIX clients in Configuration Manager | Microsoft Learn](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/install/deploying-clients-to-unix-and-linux-computers)
  - On-prem AD: Inventory management, hardware data, Windows/Linux support
- Microsoft Learn – Overview of Intune device actions

  - [Device actions in Microsoft Intune | Microsoft Learn](https://learn.microsoft.com/en-us/mem/intune/remote-actions/device-management)
  - Cloud/Entra: Remote actions (retire, wipe, compliance), what can/can’t be done with Linux/Windows

</details>
