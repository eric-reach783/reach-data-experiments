
### Key Types of attacks, not exhaustive:

Interesting Findings when joined with MITRE ATT&CK data:
 - Attack Path Components: Information about specific nodes and edges in BloodHound graphs 
    (e.g., group membership, ACL abuses, GPO links, or session data) could map to MITRE ATT&CK techniques like "Exploit Public-Facing Application" (TA0001) or "Initial Access" via credentials
 - Tool Usage: Details about tools used in attacks (e.g., Rubeus for Kerberoasting or Certify for certificate exploitation)
    could align with MITRE ATT&CK techniques such as "Kerberoasting" (T1558) or "Exploitation for Client Execution" (T1059).  
 - Threat Actor Behavior: Data on lateral movement patterns or privilege escalation paths might correlate with known threat actor tactics documented in MITRE ATT&CK, such as "Domain Trust Abuse" (TA0006) 


Service Account Attacks
- Password Guessing/Spraying: Attackers attempt to find service account passwords through common password attempts or by searching file shares and key vaults
- Kerberoasting: Any AD user can request Kerberos service tickets for accounts with Service Principal Names (SPNs), then crack these tickets offline to obtain passwords

AD Certificate Services (ADCS) Attacks path coverage
- ESC1, ESC3, ESC6a/6b, ESC9a/9b, ESC10a/10b, ESC13, ESC14: Various certificate-based escalation techniques
- GoldenCert: Attacks leveraging compromised certificate authorities
- Certificate enrollment abuse: Exploiting enrollment permissions and templates

Trust Relationship Attacks
- SID History Spoofing: Manipulating Security Identifier history across domain trusts to gain elevated privileges
- Cross-forest attacks: Exploiting trust relationships between different AD forests


- Domains of trust
  - Identify and map trust relationships between domains.
  - Detect potential misconfigurations or overly permissive trusts. 
  - Analyze paths that could be exploited for lateral movement or privilege escalation.

### Summary of Key Use Cases

| **Category**             | **Actionable Information**                                                                                     |
|--------------------------|----------------------------------------------------------------------------------------------------------------|
| Privilege Escalation     | Users with direct or indirect access to admin groups, nested group chains.                                     |
| Lateral Movement         | Cross-domain trusts, user/computer access via RDP, PSRemoting, etc.                                            |
| Policy Misconfigurations | GPOs with insecure settings, ACEs allowing Everyone access, misconfigured password policies.                   |
| Attack Surface Analysis  | Orphaned accounts, unowned computers, exposed SPNs or GPP entries.                                             |
| Security Controls        | Missing audit policies on DCs/GPOs, unrestricted delegation, weak MFA enforcement.                             |
| Shadow Admin Detection   | Users/service accounts with indirect access to admin groups via ACLs or nested memberships.                    |
| Hybrid Environment Risks | Azure AD trusts without isolation, cloud service principals with on-premises access.                           |
| Account Lifecycle        | Inactive users in privileged groups, service accounts without expiry or complexity policies.                   |


#### Examples of specific detections possible:
1. Privilege escalation paths—sequences of group memberships or permissions enabling unauthorized elevation of privileges
2. Trust relationships—both horizontal (e.g., domain trusts) and vertical (e.g., nested groups) connections that may expose attack vectors
3. Rogue domain controllers—unusual or non-compliant DCs with suspicious access patterns or configurations
4. Users in privileged groups—identifying accounts directly or indirectly part of high-risk groups like Domain Admins
5. Unconstrained delegation misconfigurations—computers or users granted full trust to delegate credentials without restrictions
6. Overprivileged service accounts—accounts with unnecessary admin rights or access to sensitive resources
7. Password spray targets—users with weak password policies or accounts that may be vulnerable to credential stuffing attacks
8. Orphaned objects—unused AD entities (e.g., computers, users) that might be exploited for lateral movement
9. SPN (Service Principal Name) misuse—accounts improperly configured with SPNs, potentially enabling pass-the-ticket attacks
10. AdminSDHolder anomalies—misconfigured permissions on the AdminSDHolder object affecting group policy inheritance
11. Lateral movement opportunities—access paths between systems or users that could facilitate network traversal
12. Group Policy Object (GPO) overreach—GPOs granting excessive permissions to unintended users or computers
13. Insecurely configured ACLs—Access Control Lists on critical objects that allow unrestricted access
14. High-value targets—users or systems with broad administrative rights, often prioritized for further exploitation
15. Delegation chains—sequences of delegated permissions that could be abused to bypass security controls


---

### **Privilege Escalation Vectors**
- **Direct Membership in Tier Zero Groups**:  
  Identify users, computers, or service accounts directly in groups like `Domain Admins`, `Enterprise Admins`, or other high-privilege groups (e.g., `Administrators` on domain controllers).  
  *Example*: Users with direct access to `Domain Admins`.

- **Nested Group Membership Paths**:  
  Surface users who gain admin privileges through nested group memberships, which are harder to detect via traditional tools.  
  *Example*: User in a group that is nested into another group which has access to Tier Zero nodes.

- **High-Risk Group Memberships (e.g., Everyone)**:  
  Find groups like `Everyone`, `Domain Users`, or other overly broad memberships that might grant unintended privileges to low-trust entities.  
  *Example*: A user in a group that is itself a member of an admin group through indirect relationships.

- **Service Accounts with Excessive Privileges**:  
  Highlight service accounts (e.g., SQL Server, Exchange) that are members of administrative groups or have permissions to modify critical objects.  
  *Example*: A service account in `Domain Admins` or with `GenericAll` access to a domain controller.

```cypher
MATCH (u:User)-[:MemberOf]->(g:Group)
WHERE g.name = "Domain Admins"
RETURN u
```
---

### **Lateral Movement Opportunities**
- **User Access to Computers (e.g., RDP, PSRemoting)**:  
  Identify users who can remotely access computers (via `CanRDPTo`, `CanPSRemoteTo`, etc.), potentially enabling lateral movement.  
  *Example*: A regular user has direct access to a domain controller via `CanRDPTo`.

- **Computer Accounts with Administrative Privileges**:  
  Find computers that are members of admin groups or have permissions to modify other computers (e.g., through `GenericAll` or `WriteDacl`).  
  *Example*: A workstation computer in the `Domain Admins` group.

- **Cross-Domain Trust Relationships**:  
  Surface trust relationships between domains, especially if they allow lateral movement without proper isolation.  
  *Example*: A one-way trust from Domain B to Domain A that could be exploited for domain-wide access.

- **Unconstrained Delegation**:  
  Highlight accounts with `TrustedForDelegation` enabled and no specific service account restrictions, which are vulnerable to Pass-the-Ticket attacks.  
  *Example*: A user with unconstrained delegation can impersonate any account in the forest.

```cypher
MATCH (p:Base)-[:MemberOf]->(g:Group)
WHERE p.domainsid <> g.domainsid
RETURN DISTINCT p, g
LIMIT 1000
```
---

### **Unusual/High-Risk Relationships**
- **Cross-Domain Group Membership**:  
  Detect users/computers from one domain being members of groups in another domain (e.g., a user in Domain A is part of `Domain Admins` in Domain B).  
  *Example*: A service account from an external domain has access to privileged resources in the internal domain.

- **Password Spray Targets**:  
  Identify users who are not restricted by logon constraints (e.g., `NoLogonRestrictions`) or have weak password policies, making them vulnerable to brute-force attacks.  
  *Example*: A user without a password complexity policy and no logon restrictions.

- **Users with "Do Not Enforce" Password Policy**:  
  Highlight accounts that are not governed by the domain's standard password complexity requirements (often used for service accounts).  
  *Example*: A SQL service account with `pwdLastSet` set to `-1` and `UserMayNotChangePassword` enabled.

- **High-Risk ACLs or ACEs**:  
  Find objects (e.g., GPOs, computers, groups) with overly permissive Access Control Entries (ACEs), such as allowing any user to modify the object.  
  *Example*: A domain controller's `NTDS Settings` OU is editable by `Domain Users`.

- **Orphaned or Unused Objects**:  
  Detect inactive users, unused service accounts, or dormant computers that might still hold permissions due to misconfiguration.

---

### **Policy Misconfigurations**
- **GPOs Applied to High-Risk Groups/Objects**:  
  Identify Group Policy Objects (GPOs) applied to groups like `Domain Admins` that could enforce insecure settings (e.g., no password complexity).  
  *Example*: A GPO applied to Domain Admins with "Password must meet complexity requirements" disabled.

- **Overly Permissive ACEs in ACLs**:  
  Surface objects with ACEs allowing unauthorized access, such as `Everyone`, `Domain Users`, or even `Authenticated Users`.  
  *Example*: A file server's folder has full control for `Authenticated Users`.

- **Misconfigured Trust Relationships**:  
  Highlight trusts that are not properly isolated (e.g., transitive trusts between untrusted domains) or lack access controls.  
  *Example*: A one-way trust from an external partner domain allows lateral movement to internal resources.

- **Default Group Memberships**:  
  Find users in default groups like `Domain Users`, `Schema Admins`, or `Enterprise Admins` without proper justification.  
  *Example*: A user with no special role is directly added to `Enterprise Admins`.

- **Insecure Default Permissions on Critical Objects**:  
  Highlight objects (e.g., domain controllers, GPO links) that have insecure permissions by default.  
  *Example*: A domain controller's `Default Domain Policy` GPO has ACEs allowing modification by non-admin users.

```cypher
MATCH (u:User)-[:MemberOf*1..5]->(g:Group)-[:CanRDPTo|CanPSRemoteTo]->(dc:Computer)
WHERE dc.isdomaincontroller = true
RETURN u, g, dc
```
---

### **Attack Surface Analysis**
- **Non-Owned Computers**:  
  Identify computers in the environment where the owning user or group is not explicitly defined (e.g., unowned machines).  
  *Example*: A computer account without an owner or with a generic owner like `Domain Users`.

- **Computers with No Password Policy Enforcement**:  
  Find computers that are not governed by password complexity policies, making them vulnerable to offline brute-force attacks.  
  *Example*: A workstation in the AD forest has no logon restrictions.

- **SPNs Misconfigured for Kerberoasting**:  
  Surface service accounts (e.g., `HTTP/ServiceName`) with SPNs configured but without proper protection (e.g., `ServicePrincipalNames` on user objects).  
  *Example*: A user account with an SPN and no password complexity policy.

- **High-Risk Group Membership Chains**:  
  Highlight users who are part of multiple nested groups, creating long attack paths to Tier Zero nodes.  
  *Example*: User → GroupA → GroupB → Domain Admins (via 3+ hops).

```cypher
MATCH (u:User)
WHERE u.serviceprincipalnames IS NOT NULL AND u.passwordcomplexity = false
RETURN u
```
---

### **Security Controls and Hardening**
- **Missing Audit Policies on Critical Objects**:  
  Find objects or groups that lack audit policies (e.g., `Audit Object Access`) to track modifications or access attempts.  
  *Example*: A domain controller object has no audit policy enabled for changes.

- **Lack of Monitoring on High-Risk Accounts**:  
  Identify accounts with elevated privileges but without proper monitoring (e.g., logs, alerts) in place.  
  *Example*: No event log monitoring configured for a service account in `Enterprise Admins`.

- **Weak Password Policies for Service Accounts**:  
  Highlight service accounts with weak or no password policies (e.g., never expires, no complexity).  
  *Example*: A service account with `PasswordNeverExpires` and `UserMayNotChangePassword` set.

- **Unrestricted Delegation Rights**:  
  Find accounts that can delegate without restrictions (`TrustedForDelegation`), which could be exploited for Pass-the-Ticket or Golden Ticket attacks.  
  *Example*: A user in Domain A is allowed to delegate to any service principal across the forest.

---

### **Compliance and Policy Audits**
- **Verification of Least Privilege**:  
  Confirm that no user has unnecessary administrative rights (e.g., non-admin users in `Domain Admins` or other admin groups).  
  *Example*: A junior employee is a member of `Enterprise Admins`.

- **Checking for "Everyone" Group Access to Resources**:  
  Identify resources where the `Everyone` group has access, which can be exploited by any authenticated user.  
  *Example*: A file share with permissions granted to `Everyone` (not restricted).

- **Audit User Account Lockout Policies**:  
  Ensure that lockout policies are enabled and configured appropriately for all accounts (especially admin accounts).  
  *Example*: Domain Admins accounts have a password lockout threshold of 0.

- **Reviewing Group Policy Preferences (GPP)**:  
  Find GPOs with sensitive settings exposed in plaintext via GPP (e.g., credentials stored as `Registry` or `File System` items).  
  *Example*: A GPO containing unencrypted domain admin passwords.

- **Checking for Insecure Default Trusts**:  
  Verify that all trusts are properly secured and not allowing lateral movement without constraints.  
  *Example*: A trust between two domains has transitive access but no isolation controls.

---

### **Shadow Admins (Indirect Administrative Access)**
- **Users with Indirect Access to Tier Zero Groups**:  
  Identify users who are not explicitly in admin groups but gain access via nested group memberships or ACLs.  
  *Example*: A user is part of a group that has `WriteDacl` permissions on `Domain Admins`.

- **Service Accounts with Shadow Admin Privileges**:  
  Highlight service accounts that can modify administrative groups or domain controllers via ACEs.  
  *Example*: A SQL service account has `GenericAll` access to the `Enterprise Admins` group.

- **Computers with Indirect Administrative Access**:  
  Find computers (e.g., workstations) that are members of admin groups through nested relationships.  
  *Example*: A workstation is a member of a group which is in turn a member of `Domain Admins`.

---

### **Cloud/On-Premises Hybrid Environments**
- **Misconfigured Azure AD Trusts**:  
  Surface hybrid trusts between on-premises and cloud environments that lack proper isolation or access controls.  
  *Example*: A trust from an Azure AD group to on-premises `Domain Admins`.

- **Exposure of On-Premises Resources via Cloud Services**:  
  Identify cloud-based accounts (e.g., service principals) with access to on-premises resources like domain controllers or admin groups.  
  *Example*: An Azure AD application has `GenericAll` permissions over a domain controller.

- **Insecure Password Synchronization**:  
  Highlight cases where passwords are synchronized between Azure AD and on-premises AD but lack strong policies (e.g., no complexity).  
  *Example*: A user with synced credentials to cloud services but without MFA enabled.

---

### **Statistical Analysis for Risk Prioritization**
- **Number of Users in Tier Zero Groups**:  
  Quantify how many users have access to admin groups (e.g., `Domain Admins`) and flag any anomalies.  
  *Example*: 20 non-admin users in the `Enterprise Admins` group.

- **Group Membership Depth Analysis**:  
  Identify deeply nested group memberships that could be exploited for privilege escalation.  
  *Example*: A user is part of a chain of 5 groups to reach `Domain Admins`.

- **Top High-Risk Groups/Computers by Attack Path Count**:  
  Surface groups or computers with the most attack paths (e.g., many users can exploit them).  
  *Example*: The `Administrators` group has 50+ users who could potentially access it.

- **Unused or Orphaned Objects**:  
  Identify accounts, groups, or computers that are no longer in use but still hold permissions.  
  *Example*: An old user account with access to a domain controller and no activity logs.

---

### **Communication and Session Analysis**
- **Users with Sessions on High-Risk Computers**:  
  Identify users who have logged into computers with administrative privileges (e.g., domain controllers).  
  *Example*: A service account has sessions on the primary domain controller.

- **Computer Accounts with Insecure Kerberos Delegation**:  
  Highlight workstations or servers that can delegate credentials to other resources without constraints.  
  *Example*: A file server is configured for unconstrained delegation and has access to sensitive systems.

- **Unrestricted Remote PowerShell Access (CanPSRemoteTo)**:  
  Surface users who have `CanPSRemoteTo` permissions on critical computers (e.g., DCs, servers with sensitive data).  
  *Example*: A junior user can PSRemotely into a domain controller via group membership.

---

### **Account Lifecycle and Configuration**
- **Accounts Without Expiry**:  
  Identify service accounts or users with passwords that never expire (e.g., `PasswordNeverExpires` set).  
  *Example*: A legacy application account in the `Domain Admins` group without password expiry.

- **Users with No Password Policy Enforced**:  
  Find accounts where the "Do Not Enforce" password policy is applied, bypassing domain-wide requirements.  
  *Example*: An admin user has no password complexity rules enforced due to a misconfigured GPO.

- **Account Inactivity and Dormancy**:  
  Detect inactive users or computers that still hold access, increasing attack surface risk.  
  *Example*: A user last logged in over 90 days ago but is part of the `Domain Admins` group.

---

### **Attack Path Identification**
- **Shortest Paths from Non-Admin Users to Tier Zero Nodes**:  
  Identify users who can reach administrative groups or domain controllers with minimal steps (e.g., 2 hops).  
  *Example*: A user is part of a group that has `WriteDacl` on a second group, which is in `Domain Admins`.

- **Attack Paths Through Trust Relationships**:  
  Surface paths from one domain to another via trust relationships (e.g., a non-admin in Domain A can exploit trusts to move to Domain B).  
  *Example*: A user in Domain A exploits a one-way trust to access resources in Domain B.

- **Potential for Kerberoasting or Pass-the-Ticket**:  
  Identify service accounts with SPNs and no password complexity policies.  
  *Example*: A SQL service account has `HTTP/SQLServer` as an SPN but lacks strong passwords.

---

### 14. **Training and Awareness**
- **Visualizing Attack Paths for Red Team Exercises**:  
  Use BloodHound to map out realistic attack paths (e.g., non-admin user → nested group → admin group) for training purposes.  
  *Example*: A scenario where a user gains access to `Domain Admins` through three nested groups.

- **Highlighting Common Misconfigurations**:  
  Create dashboards or reports that show common vulnerabilities, such as:
  - Service accounts in admin groups.
  - Default domain trusts with no isolation.
  - Overly permissive ACLs on GPO links or DC objects.

---

### **Reporting and Remediation**
- **Generate Reports for Compliance Audits**:  
  Export findings like "users in Tier Zero groups" or "cross-domain trust relationships" to share with IT teams for remediation.  
  *Example*: A report showing 10 users in the `Administrators` group of a domain controller.

- **Automated Remediation Recommendations**:  
  Flag objects (e.g., groups, GPOs) that need immediate attention and suggest steps like:
  - Removing users from admin groups.
  - Restricting ACEs to only necessary entities.
  - Enabling password complexity for service accounts.

---


Traversable Edges:
These represent relationships that can be abused to obtain control over a connected node. Non-traversable edges can be combined to create a traversable
edge. `DCSync` is a good example. This is done in Bloodhounds post-processing.
```ascii
AbuseTGTDelegation
CanPSRemote
HasSession
ADCSESC1
CanRDP
HasTrustKeys
ADCSESC10a
CoerceAndRelayNTLMToADCS
MemberOf
ADCSESC10b
CoerceAndRelayNTLMToLDAP
Owns
ADCSESC13
CoerceAndRelayNTLMToLDAPS
OwnsLimitedRights
ADCSESC3
CoerceAndRelayNTLMToSMB
ReadGMSAPassword
ADCSESC4
CoerceToTGT
ReadLAPSPassword
ADCSESC6a
Contains
SameForestTrust
ADCSESC6b
DCFor
SpoofSIDHistory
ADCSESC9a
DCSync
SQLAdmin
ADCSESC9b
DumpSMSAPassword
SyncedToEntraUser
AddAllowedToAct
ExecuteDCOM
SyncLAPSPassword
AddKeyCredentialLink
ForceChangePassword
WriteAccountRestrictions
AddMember
GPLink
WriteDacl
AddSelf
GenericAll
WriteGPLink
AdminTo
GenericWrite
WriteOwner
AllExtendedRights
GoldenCert
WriteOwnerLimitedRights
AllowedToAct
HasSIDHistory
WriteSPN
AllowedToDelegate
```

Non-Traversable Edges:
```ascii
CrossForestTrust
HostsCAService
OwnsRaw
DelegatedEnrollmentAgent
IssuedSignedBy
PublishedTo
Enroll
LocalToComputer
RemoteInteractiveLogonPrivilege
EnrollOnBehalfOf
ManageCA
RootCAFor
EnterpriseCAFor
ManageCertificates
TrustedForNTAuth
ExtendedByPolicy
MemberOfLocalGroup
WriteOwnerRaw
GetChanges
NTAuthStoreFor
WritePKIEnrollmentFlag
GetChangesAll
OIDGroupLink
WritePKINameFlag
GetChangesInFilteredSet
```

