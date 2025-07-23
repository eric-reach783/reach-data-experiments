#### Map domains of trust:

Domain trusts are formal relationships between two Active Directory (AD) domains that permits authentication and authorization across domain boundaries. These trust relationships are critical in multi-domain or multi-forest environments, as they define how users and resources interact across different security domains.

```cypher
MATCH p = (:Domain)-[:SameForestTrust|CrossForestTrust]->(:Domain)
RETURN p
LIMIT 1000
```

#### Locations of Tier Zero/High value objects:

```cypher
MATCH p = (t:Base)<-[:Contains*1..]-(:Domain)
WHERE COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0'
RETURN p
LIMIT 1000
```

#### OU Structure

Organizational Unit (OU) is a node representing a container object within Active Directory (AD). OUs are used to logically group users, computers, groups, and other OUs, facilitating administrative delegation and the application of Group Policy Objects (GPOs).

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:OU)
RETURN p
LIMIT 1000
```

### Dengerous Privledeges

#### Paths from domain users to Tier Zero objects

```cypher
MATCH p=shortestPath((s:Group)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|SyncedToEntraUser|CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|WriteOwnerLimitedRights|OwnsLimitedRights|CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS|Contains|DCFor|SameForestTrust|SpoofSIDHistory|AbuseTGTDelegation*1..]->(t))
WHERE COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0' AND s.objectid ENDS WITH '-513' AND s<>t
RETURN p
LIMIT 1000
```

#### Principles with DCSync Privileges:

```cypher
MATCH p=(:Base)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain)
RETURN p
LIMIT 1000
```

#### Principles with foriegn domain group membership: cross-domain membership relationships

These are high-risk scenarios because they indicate that an entity from one domain has access to a group (and thus potential privileges) in another domain.

- Lateral movement across domains.
- Privilege escalation by leveraging group membership.
- Unauthorized control over resources outside the principal’s native domain.

```cypher
MATCH p=(s:Base)-[:MemberOf]->(t:Group)
WHERE s.domainsid<>t.domainsid
RETURN p
LIMIT 1000
```

```cypher
MATCH p=(s:Group)-[:AdminTo]->(:Computer)
WHERE s.objectid ENDS WITH '-513'
RETURN p
LIMIT 1000
```

## Entra/Azure Specific Queries

#### Shortest path to Entra users to Teir Zero/High value targets:

In Azure AD (Entra ID) environments this query identifies the shortest privilege escalation or lateral movement paths from any Entra (Azure AD) user (AZUser) to highly privileged Tier Zero roles or accounts (e.g., Global Administrator, Privileged Authentication Administrator).

Most common attack paths that this shows:

1. **User with Privileged Role Assignment**: An ordinary user is assigned to a group that has the `Global Administrator` role, either directly or via nested group membership.
2. **Role Escalation via App Ownership**: A user owns an application or service principal that has privileged roles, allowing them to escalate to Tier Zero by abusing app credentials or permissions.
3. **Privileged Access via Delegated Admin**: A user is granted `Privileged Authentication Administrator` or similar roles through delegated admin rights, enabling them to reset passwords or assign roles to themselves or others.
4. **Lateral Movement via Managed Identities**: A user can control a managed identity (e.g., via `AZManagedIdentity` or `AZOwner`), which in turn has privileged access, allowing indirect escalation.
5. **Chained Group Memberships**: A user is a member of a group, which is a member of another group, eventually leading to a group with Tier Zero privileges (multi-hop `AZMemberOf` relationships).

```cypher
MATCH p=shortestPath((s:AZUser)-[:AZAvereContributor|AZContributor|AZGetCertificates|AZGetKeys|AZGetSecrets|AZHasRole|AZMemberOf|AZOwner|AZRunsAs|AZVMContributor|AZAutomationContributor|AZKeyVaultContributor|AZVMAdminLogin|AZAddMembers|AZAddSecret|AZExecuteCommand|AZGlobalAdmin|AZPrivilegedAuthAdmin|AZGrant|AZGrantSelf|AZPrivilegedRoleAdmin|AZResetPassword|AZUserAccessAdministrator|AZOwns|AZCloudAppAdmin|AZAppAdmin|AZAddOwner|AZManagedIdentity|AZAKSContributor|AZNodeResourceGroup|AZWebsiteContributor|AZLogicAppContributor|AZMGAddMember|AZMGAddOwner|AZMGAddSecret|AZMGGrantAppRoles|AZMGGrantRole|SyncedToADUser|AZRoleEligible|AZContains*1..]->(t:AZBase))
WHERE (t:Tag_Tier_Zero) AND t.name =~ '(?i)^(Global Administrator|User Administrator|Cloud Application Administrator|Authentication Policy Administrator|Exchange Administrator|Helpdesk Administrator|Privileged Authentication Administrator).*$' AND s<>t
RETURN p
LIMIT 1000
```

Sources:

- [BloodHound documentation](https://bloodhound.readthedocs.io/en/latest/)
- [Azure privilege escalation paths](https://posts.specterops.io/azure-privilege-escalation-vectors-9b22b55cfc53)
- [Microsoft Entra roles](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference)
- [BloodHound attack path analysis](https://github.com/BloodHoundAD/BloodHound)
- [AzureHound (BloodHound for Azure)](https://github.com/BloodHoundAD/AzureHound)

Shortest path to privledge roles:

This query identifies the shortest privilege escalation or lateral movement paths from any Azure AD (Entra) principal (AZBase) to highly privileged Azure AD roles (e.g., Global Administrator, Privileged Authentication Administrator).

Most common attack paths that this shows:

1. **Direct Role Assignment:** A user or service principal is directly assigned a privileged role.
2. **Nested Group Escalation:** A principal is a member of a group, which is nested within another group, eventually leading to a group with a privileged role.
3. **Role Escalation via App Ownership:** A principal owns an application or service principal that has a privileged role, enabling privilege escalation.
4. **Privilege via Delegated Admin:** A principal is granted a privileged role through delegated admin rights or role assignment chains.
5. **Lateral Movement via Managed Identities:** A principal controls a managed identity or resource with privileged access, allowing indirect escalation to a privileged role.

```cypher
MATCH p=shortestPath((s:AZBase)-[:AZAvereContributor|AZContributor|AZGetCertificates|AZGetKeys|AZGetSecrets|AZHasRole|AZMemberOf|AZOwner|AZRunsAs|AZVMContributor|AZAutomationContributor|AZKeyVaultContributor|AZVMAdminLogin|AZAddMembers|AZAddSecret|AZExecuteCommand|AZGlobalAdmin|AZPrivilegedAuthAdmin|AZGrant|AZGrantSelf|AZPrivilegedRoleAdmin|AZResetPassword|AZUserAccessAdministrator|AZOwns|AZCloudAppAdmin|AZAppAdmin|AZAddOwner|AZManagedIdentity|AZAKSContributor|AZNodeResourceGroup|AZWebsiteContributor|AZLogicAppContributor|AZMGAddMember|AZMGAddOwner|AZMGAddSecret|AZMGGrantAppRoles|AZMGGrantRole|SyncedToADUser|AZRoleEligible|AZContains*1..]->(t:AZRole))
WHERE t.name =~ '(?i)^(Global Administrator|User Administrator|Cloud Application Administrator|Authentication Policy Administrator|Exchange Administrator|Helpdesk Administrator|Privileged Authentication Administrator).*$' AND s<>t
RETURN p
LIMIT 1000
```

Sources:

- [BloodHound documentation](https://bloodhound.readthedocs.io/en/latest/)
- [Azure privilege escalation paths](https://posts.specterops.io/azure-privilege-escalation-vectors-9b22b55cfc53)
- [Microsoft Entra roles](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference)
- [BloodHound attack path analysis](https://github.com/BloodHoundAD/BloodHound)
- [AzureHound BloodHound for Azure](https://github.com/BloodHoundAD/AzureHound)

#### Devices with unsupported Operating Systems:

Identifies Azure AD (Entra) devices running Windows operating systems with versions that are considered unsupported or out-of-date. You can make the matching be anything, such as specific OS, the version number, etc.

Most common attack paths that this shows:

1. **Unpatched Vulnerabilities:** Devices on unsupported OS versions do not receive security patches, increasing risk of exploitation.
2. **Lack of Vendor Support:** No official support from Microsoft, making incident response and troubleshooting more difficult.
3. **Incompatibility with Security Tools:** Modern security solutions may not function correctly on legacy systems.
4. **Increased Attack Surface:** Older OS versions may have known, widely exploited vulnerabilities.
5. **Compliance Violations:** Use of unsupported OSs may breach regulatory or organizational security policies.

```cypher
MATCH (n:AZDevice)
WHERE n.operatingsystem CONTAINS 'WINDOWS'
AND n.operatingsystemversion =~ '(10.0.19044|10.0.22000|10.0.19043|10.0.19042|10.0.19041|10.0.18363|10.0.18362|10.0.17763|10.0.17134|10.0.16299|10.0.15063|10.0.14393|10.0.10586|10.0.10240|6.3.9600|6.2.9200|6.1.7601|6.0.6200|5.1.2600|6.0.6003|5.2.3790|5.0.2195).?.*'
RETURN n
LIMIT 100
```

Sources:

- [Microsoft Windows lifecycle fact sheet](https://learn.microsoft.com/en-us/lifecycle/products/windows)
- [BloodHound documentation](https://bloodhound.readthedocs.io/en/latest/)
- [AzureHound (BloodHound for Azure)](https://github.com/BloodHoundAD/AzureHound)

#### Foriegn principals in the Teir Zero/High Value

Service principals that are tagged as Tier Zero (high value) but are owned by a different Azure AD tenant (i.e., a foreign organization). This is high risk scenario.

1. **External Control of Critical Resources:** Foreign tenants can manage or manipulate Tier Zero assets.
2. **Supply Chain Attacks:** Compromise of a partner or vendor tenant could cascade into your environment.
3. **Unmonitored Privileged Access:** External entities may bypass local monitoring and controls.
4. **Data Exfiltration:** Foreign principals may access or extract sensitive data.
5. **Regulatory and Compliance Violations:** External privileged access may breach organizational or legal requirements.

```cypher
MATCH (n:AZServicePrincipal)
WHERE (n:Tag_Tier_Zero)
AND NOT toUpper(n.appownerorganizationid) = toUpper(n.tenantid)
AND n.appownerorganizationid CONTAINS '-'
RETURN n
LIMIT 100
```

Sources:

- [BloodHound documentation](https://bloodhound.readthedocs.io/en/latest/)
- [AzureHound (BloodHound for Azure)](https://github.com/BloodHoundAD/AzureHound)
- [Microsoft Entra service principal documentation](https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
