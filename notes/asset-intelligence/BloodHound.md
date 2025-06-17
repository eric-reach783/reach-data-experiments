

Notes:
- Using ACEs for enumerating ACEs across all AD objects to map out ACL-based attack paths
    -https://wald0.com/?p=112
```text
Critical ACE permissions (edges) that attackers can abuse to take over accounts or groups:

GenericAll – full control over an object (reset passwords, manage group membership)
GenericWrite – ability to modify object attributes (e.g., password, logon scripts)
WriteDACL – ability to modify an object’s DACL, effectively changing its permissions 
WriteOwner – ability to take ownership of an object, granting ultimate control 
ForceChangePassword – ability to change another user's password without knowing theirs
AddMember / AddMembers – permission to add members to groups (e.g., adding self to Domain Admins)
ResetPassword – resetting a user’s password directly
```
- BH scans usually contain around 7 JSON files



## Active Directory:

Security Boundaries:
- https://specterops.github.io/TierZeroTable/ <- This includes Tier Zero Queries
- https://github.com/SpecterOps/TierZeroTable
- https://posts.specterops.io/what-is-tier-zero-part-1-e0da9b7cdfca


Tier Zero - controls everything in the domain
Non-Tier Zero controls nothing by default

3 main groups to think about, People, Process, and Tehcnology

Things To Document and Track

- Naming conventions of OUs, computers, users, groups
- DNS, network, and DHCP configurations
- An intimate understanding of all GPOs and the objects that they are applied to
- Assignment of FSMO roles
- Full and current application inventory
- A list of all enterprise hosts and their location
- Any trust relationships we have with other domains or outside entities
- Users who have elevated permissions

### Systems in an AD environment that are almost always Tier Zero:

- PKI (Public Key Infrastructure) / ADCS (Active Directory Certificate Services)
  - Root CA (Certificate Authority) server 
  - Subordinate CAs
- ADFS (Active Directory Federation Services)
  - Note: The Web Application Proxy (WAP) servers should be in a separate AD forest (DMZ or extranet network) and are not considered Tier Zero.
- Azure AD Connect servers and accounts 
  - Incl. servers with PTA agents if Pass-Through Authentication (PTA) is enabled.
- Privileged Access Management systems (such as Delinea or CyberArk)
- GPO Administration tools (such as Quest GPO Admin or AGPM)
- Read-Only Domain Controller (RODC) computer objects 
  - Read about why the RODC computer objects are Tier Zero and how RODCs should be configured to protect Tier Zero here: What is Tier Zero - Part 2.
- Anything else your organization already classifies as Tier Zero, such as Privileged Access Workstations.
#### Sources:
- https://bloodhound.specterops.io/get-started/security-boundaries/tier-zero-members
- https://github.com/SpecterOps/TierZeroTable/
- https://posts.specterops.io/what-is-tier-zero-part-1-e0da9b7cdfca

### Useful workflows/joins:
- Map the Queries to MITRE ATT&CK and D3F3ND
  - https://medium.com/falconforce/graphing-mitre-att-ck-via-bloodhound-87c11aadc119
EX:
#### 2. **Non-Tier 0 DCSync Accounts**
- https://attack.mitre.org/techniques/T1003/006/
```cypher


MATCH p = allShortestPaths((b:Base)-[:MemberOf|:GenericAll|:DCSync*1..]->(d:Domain))
WHERE b <> d
  AND NOT "admin_tier_0" IN split(b.system_tags, " ") OR b.system_tags is NULL
RETURN p
LIMIT 1000d
```

Queries:

- https://github.com/ZephrFish/Bloodhound-CustomQueries/blob/main/customqueries.json
- https://github.com/zblurx/BloodHoundCustomQueries/blob/main/customqueries.json
- https://github.com/CompassSecurity/BloodHoundQueries - Legacy Bloodhound
- https://github.com/CompassSecurity/bloodhoundce-resources


What are the findsings
what vcan we do with them
how can we use it
what are the findings attaced to
will there be saml

- can you add a device to AD without joining 

## BloodHound Use Cases & Findings:
Links: 
- https://posts.specterops.io/cypher-queries-in-bloodhound-enterprise-c7221a0d4bb3

Use Cases (not limited to)
  - Identifying Domain Trusts
    - This may be the case in situations where an organization allows users in one domain to access resources from another domain,
      but not in the other direction. It may also be a misconfiguration where a trust relationship was never severed.
    ```cypher
    MATCH p=(n:Domain)-[]->(m:Domain)
    RETURN p
    ```
  - Identifying admin rights held by non-administrative accounts
    - Helps find if a user has been added and is now over-privileged, presenting a potential attack path for an attacker.
    ```cypher
    MATCH p=(m:User)-[r:AdminTo]->(n:Computer)
    WHERE NOT m.name CONTAINS “.helpdesk”
    RETURN m
    ```
  - Identifying nested group memberships in Tier Zero that may be coming from other domains
    - Identify Tier Zero groups that exist in a particular domain
    - Identify nesting under another Tier Zero group in a separate domain within a forest
    This allows us to see instances where bi-directional trust dramatically increases Tier Zero 
    and expands the potential for undesirable Attack Paths within a forest. It is problematic to begin with when non-Tier Zero users can reach Tier Zero,
    but our attack surface is dramatically increased when non-Tier Zero users in Domain B can reach Tier Zero in
    Domain A because of improper nesting of non-Tier Zero principals within Tier Zero groups.
    ```cypher
    MATCH p=((n:Group)-[:MemberOf*..]->(t:Group))
    WHERE n.domainsid <> t.domainsid AND coalesce(n.system_tags,"") CONTAINS ('tier_0') AND coalesce(t.system_tags,"") CONTAINS ('tier_0')
    AND NOT n.objectid ENDS WITH "-512"
    AND NOT n.objectid ENDS WITH "-519"
    RETURN p
    ```

  -  no prebuilt query for accounts based on a last name.
Surfaceable Findings
  - Tier Zero Attack Paths

AD Recommendations:
People
- The organization should have a strong password policy, with a password filter that disallows the use of common words (i.e., welcome, password, names of months/days/seasons, and the company name). If possible, an enterprise password manager should be used to assist users with choosing and using complex passwords.
- Rotate passwords periodically for all service accounts.
- Disallow local administrator access on user workstations unless a specific business need exists.
- Disable the default RID-500 local admin account and create a new admin account for administration subject to LAPS password rotation.
- Implement split tiers of administration for administrative users. Too often, during an assessment, you will gain access to Domain Administrator credentials on a computer that an administrator uses for all work activities.
- Clean up privileged groups. Does the organization need 50+ Domain/Enterprise Admins? Restrict group membership in highly privileged groups to only those users who require this access to perform their day-to-day system administrator duties.
      Where appropriate, place accounts in the Protected Users group.
- Disable Kerberos delegation for administrative accounts (the Protected Users group may not do this)


