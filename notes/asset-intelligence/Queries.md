# BloodHound CE Custom Queries


#### Find cross-domain edges pointing to Tier Zero nodes:
This query identifies relationships from external domains to Tier Zero nodes. (trusted domains, possibly other use cases)
```cypher
MATCH p = (x:Base)-[:AD_ATTACKS]->(y:Base)
WHERE y.system_tags CONTAINS 'admin_tier_0' AND x.domain <> y.domain
RETURN p
```

#### Find internal paths leading to Tier Zero nodes:
This highlights attack paths within the same domain to Tier Zero nodes.
```cypher
MATCH p = (x:Base)-[:AD_ATTACKS]->(y:Base)
WHERE x.domain = y.domain AND y.system_tags CONTAINS 'admin_tier_0' AND NOT COALESCE(x.system_tags, '') CONTAINS 'admin_tier_0'
RETURN p
```

#### Retrieve all Tier Zero nodes directly:
This filters nodes with the admin_tier_0 tag in their system properties.
```cypher
MATCH (n:Base)
WHERE n.system_tags CONTAINS 'admin_tier_0'
RETURN n
```


## Domain

### Domains

```cypher
MATCH (d:Domain)
RETURN d
LIMIT 1000
```

### Domains with Machine Account Quota > 0

```cypher
MATCH (d:Domain)
WHERE toInteger(d.machineaccountquota) > 0
RETURN d
LIMIT 1000
```

### Domain Controllers

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:Computer {isdc: true})
RETURN p
LIMIT 1000
```

## Accounts

### Interesting Objects by Keywords

```cypher
UNWIND ['admin', 'empfindlich', 'geheim', 'important', 'azure', 'MSOL', 'kennwort', 'pass', 'secret', 'sensib', 'sensitiv', 'wichtig', 'backdoor', 'honey'] AS word
MATCH p = (:Domain)-[:Contains*1..]->(b:Base)
WHERE (toLower(b.name) CONTAINS toLower(word))
  OR (toLower(b.description) CONTAINS toLower(word))
RETURN p
LIMIT 1000
```

### Users with Password in Description

```cypher
UNWIND ['pass', 'pwd', 'kenn', 'login', 'cred'] AS word
MATCH p = (:Domain)-[:Contains*1..]->(u:User)
WHERE (toLower(u.description) CONTAINS toLower(word))
RETURN p
LIMIT 1000
```

### Users with Password Stored in Cleartext Password Fields

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(u:User)
WHERE u.userpassword <> ""
  OR u.unixpassword <> ""
  OR u.sfupassword <> ""
  OR u.unicodepassword <> ""
RETURN p
LIMIT 1000
```

### Users with Password Stored Using Reversible Encryption

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:Base {encryptedtextpwdallowed: true})
RETURN p
LIMIT 1000
```

### Users with Password Not Requred

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:Base {passwordnotreqd: true})
RETURN p
LIMIT 1000
```

### Users with Password Never Expires

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:Base {pwdneverexpires: true})
RETURN p
LIMIT 1000
```

### Users with Same Name in Other Domain

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(u1:User),(u2:User)
WHERE u1.samaccountname = u2.samaccountname
  AND u1.domain <> u2.domain
RETURN p
LIMIT 1000
```

### All Sessions of All Users

```cypher
MATCH p = (:Computer)-[:HasSession*1..]->(:User)
RETURN p
LIMIT 1000
```

## Privileged Accounts

### Tier 0 Objects

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(n:Base)
WHERE "admin_tier_0" IN split(n.system_tags, " ")
RETURN p
LIMIT 1000
```

### Tier 0 Users

```cypher
MATCH p = (u:User)-[:MemberOf]->(:Base)
WHERE "admin_tier_0" IN split(u.system_tags, " ")
RETURN p
LIMIT 1000
```

### Tier 0 Computers

```cypher
MATCH p = (c:Computer)-[:MemberOf]->(:Base)
WHERE "admin_tier_0" IN split(c.system_tags, " ")
RETURN p
LIMIT 1000
```

### Users in Protected Users Group

```cypher
MATCH p = (:Base)-[:MemberOf*1..]->(:Group {samaccountname: "Protected Users"})
RETURN p
LIMIT 1000
```

### Users which Cannot be Delegated ("Account is sensitive and cannot be delegated")

```cypher
MATCH p = (:Base {sensitive: true})-[:MemberOf*1..]->(:Group)
RETURN p
LIMIT 1000
```

### AdminTo Edges

```cypher
MATCH p = (u)-[:AdminTo]->(:Computer)
RETURN p
LIMIT 1000
```

### Tier 0 Users Logins on Non-Tier 0

```cypher
MATCH p = (c:Computer)-[:HasSession*1..]->(u:User)
WHERE "admin_tier_0" IN split(u.system_tags, " ")
  AND (NOT "admin_tier_0" IN split(c.system_tags, " ") OR c.system_tags is NULL)
RETURN p
LIMIT 1000
```

### Non-Tier 0 Administrators

```cypher
MATCH p = (b:Base)-[:AdminTo]->(:Computer)
WHERE NOT "admin_tier_0" IN split(b.system_tags, " ") OR b.system_tags is NULL
RETURN p
LIMIT 1000
```

### Non-Tier 0 DCSync Accounts

```cypher
MATCH p = allShortestPaths((b:Base)-[:MemberOf|:GenericAll|:DCSync*1..]->(d:Domain))
WHERE b <> d
  AND NOT "admin_tier_0" IN split(b.system_tags, " ") OR b.system_tags is NULL
RETURN p
LIMIT 1000
```

### Non-Tier 0 LAPS Read

```cypher
MATCH p = (b:Base)-[:AllExtendedRights|ReadLAPSPassword]->(:Computer)
WHERE NOT "admin_tier_0" IN split(b.system_tags, " ") OR b.system_tags is NULL
RETURN p
LIMIT 1000
```

### Non-Tier 0 RDP Access

```cypher
MATCH p = (b:Base)-[:AdminTo]->(:Computer)
WHERE NOT "admin_tier_0" IN split(b.system_tags, " ") OR b.system_tags is NULL
RETURN p
LIMIT 1000
```

## Computer Accounts

### Computer without LAPS

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:Base {haslaps: false, isdc: false})
RETURN p
LIMIT 1000
```

### Computer in Tier 0 Groups

```cypher
MATCH p = (:Computer {isdc: false})-[:MemberOf*1..]->(g:Group)
WHERE "admin_tier_0" IN split(g.system_tags, " ")
RETURN p
LIMIT 1000
```

### Computers Admin to Computers (direct)

```cypher
MATCH p = (:Computer)-[:MemberOf|HasSIDHistory*0..]->(g)-[:AdminTo]->(:Computer)
RETURN p
LIMIT 1000
```

### Computers Admin to Computers (indirect)

```cypher
MATCH p = (:Computer)-[:MemberOf*1..]->(:Base)-[:AdminTo*1..]->(:Computer)
RETURN p
LIMIT 100
```

### Computers Admin to Computers (direct and indirect but with superflous group membership information)

This query also returns all computers which are in a group, which is superflous information.

```cypher
MATCH p = allShortestPaths((c:Computer)-[:AdminTo|MemberOf*1..]->(b:Base))
WHERE c <> b
RETURN p
LIMIT 100
```

## Kerberos

### Kerberoastable Users (Accounts with SPN Set)

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(b:Base {hasspn: true})
WHERE b.samaccountname <> "krbtgt"
RETURN p
LIMIT 1000
```

### Kerberoastable Users in Tier 0 Groups

```cypher
MATCH p = shortestPath((:User {hasspn: true})-[:MemberOf*1..]->(g:Group))
WHERE "admin_tier_0" IN split(g.system_tags, " ")
RETURN p
LIMIT 1000
```

### Shortest Paths from Kerberoastable Users

```cypher
MATCH p = allShortestPaths((u:User {hasspn: true})-[:AbuseTGTDelegation|AllowedToDelegate|HasSIDHistory|ADCSESC1|CanPSRemote|HasSession|ADCSESC10a|CanRDP|MemberOf|ADCSESC10b|CoerceAndRelayNTLMToADCS|Owns|ADCSESC13|CoerceAndRelayNTLMToLDAP|OwnsLimitedRights|ADCSESC3|CoerceAndRelayNTLMToLDAPS|ReadGMSAPassword|ADCSESC4|CoerceAndRelayNTLMToSMB|ReadLAPSPassword|ADCSESC6a|CoerceToTGT|SameForestTrust|ADCSESC6b|Contains|SpoofSIDHistory|ADCSESC9a|DCFor|SQLAdmin|ADCSESC9b|DCSync|SyncedToEntraUser|AddAllowedToAct|DumpSMSAPassword|SyncLAPSPassword|AddKeyCredentialLink|ExecuteDCOM|WriteAccountRestrictions|AddMember|ForceChangePassword|WriteDacl|AddSelf|GPLink|WriteGPLink|AdminTo|GenericAll|WriteOwner|AllExtendedRights|GenericWrite|WriteOwnerLimitedRights|AllowedToAct|GoldenCert|WriteSPN*1..]->(b:Base))
WHERE u <> b
  AND u.samaccountname <> "krbtgt"
  AND u.enabled = true
  AND NOT COALESCE(u.gmsa, false) = true
  AND NOT COALESCE(u.msa, false) = true
  AND NOT "Group" IN LABELS(b)
RETURN p 
LIMIT 1000
```

- This query contains all traversable edges.

### Shortest Paths from Kerberoastable Users to Tier 0

```cypher
MATCH p = allShortestPaths((u:User {hasspn: true})-[:AbuseTGTDelegation|AllowedToDelegate|HasSIDHistory|ADCSESC1|CanPSRemote|HasSession|ADCSESC10a|CanRDP|MemberOf|ADCSESC10b|CoerceAndRelayNTLMToADCS|Owns|ADCSESC13|CoerceAndRelayNTLMToLDAP|OwnsLimitedRights|ADCSESC3|CoerceAndRelayNTLMToLDAPS|ReadGMSAPassword|ADCSESC4|CoerceAndRelayNTLMToSMB|ReadLAPSPassword|ADCSESC6a|CoerceToTGT|SameForestTrust|ADCSESC6b|Contains|SpoofSIDHistory|ADCSESC9a|DCFor|SQLAdmin|ADCSESC9b|DCSync|SyncedToEntraUser|AddAllowedToAct|DumpSMSAPassword|SyncLAPSPassword|AddKeyCredentialLink|ExecuteDCOM|WriteAccountRestrictions|AddMember|ForceChangePassword|WriteDacl|AddSelf|GPLink|WriteGPLink|AdminTo|GenericAll|WriteOwner|AllExtendedRights|GenericWrite|WriteOwnerLimitedRights|AllowedToAct|GoldenCert|WriteSPN*1..]->(b:Base))
WHERE u <> b
  AND u.samaccountname <> "krbtgt"
  AND u.enabled = true
  AND NOT COALESCE(u.gmsa, false) = true
  AND NOT COALESCE(u.msa, false) = true
  AND NOT "Group" IN LABELS(b)
  AND "admin_tier_0" IN split(b.system_tags, " ")
RETURN p
LIMIT 1000
```

- This query contains all traversable edges.

### AS-REP Roastable Users (Accounts which do Not Requre Pre-Authentication)

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:Base {dontreqpreauth: true})
RETURN p
LIMIT 1000
```

### Unconstrained Delegation Systems

```cypher
MATCH p = ()-[:CoerceToTGT]->(:Domain)
RETURN p
LIMIT 1000
```

### Shortest Path to Unconstrained Delegation Systems except DCs

```cypher
MATCH p = shortestPath((b:Base)-[:AbuseTGTDelegation|AllowedToDelegate|HasSIDHistory|ADCSESC1|CanPSRemote|HasSession|ADCSESC10a|CanRDP|MemberOf|ADCSESC10b|CoerceAndRelayNTLMToADCS|Owns|ADCSESC13|CoerceAndRelayNTLMToLDAP|OwnsLimitedRights|ADCSESC3|CoerceAndRelayNTLMToLDAPS|ReadGMSAPassword|ADCSESC4|CoerceAndRelayNTLMToSMB|ReadLAPSPassword|ADCSESC6a|CoerceToTGT|SameForestTrust|ADCSESC6b|Contains|SpoofSIDHistory|ADCSESC9a|DCFor|SQLAdmin|ADCSESC9b|DCSync|SyncedToEntraUser|AddAllowedToAct|DumpSMSAPassword|SyncLAPSPassword|AddKeyCredentialLink|ExecuteDCOM|WriteAccountRestrictions|AddMember|ForceChangePassword|WriteDacl|AddSelf|GPLink|WriteGPLink|AdminTo|GenericAll|WriteOwner|AllExtendedRights|GenericWrite|WriteOwnerLimitedRights|AllowedToAct|GoldenCert|WriteSPN*1..]->(c:Computer {isdc: false, unconstraineddelegation: true}))
WHERE b<>c
RETURN p
LIMIT 1000
```

- This query contains all traversable edges.

### Constrained Delegation

```cypher
MATCH p = (:Base)-[:AllowedToDelegate*1..]->(:Computer)
RETURN p
LIMIT 1000
```

### Constrained Delegation with Protocol Transition

```cypher
MATCH p = (:Base {trustedtoauth: true})-[:AllowedToDelegate*1..]->(:Computer)
RETURN p
LIMIT 1000
```

### Constrained Delegation without Protocol Transition

```cypher
MATCH p = (:Base {trustedtoauth: false})-[:AllowedToDelegate*1..]->(:Computer)
RETURN p
LIMIT 1000
```

### Resource Based Contrained Delegation (RBCD)

```cypher
MATCH p = (:Base)-[:AllowedToAct*1..]->(:Base)
RETURN p
LIMIT 1000
```

### Configure Resource Based Contrained Delegation (RBCD)

```cypher
MATCH p = (:Base)-[:AddAllowedToAct*1..]->(:Base)
RETURN p
LIMIT 1000
```

## Owned Objects

### Owned Objects

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(b:Base)
WHERE "owned" IN split(b.system_tags, " ")
RETURN p
LIMIT 1000
```

### Owned Objects and Their Group

```cypher
MATCH p = allShortestPaths((b1:Base)-[:MemberOf]->(b2:Base))
WHERE "owned" IN split(b1.system_tags, " ")
  AND b1 <> b2
RETURN p
LIMIT 1000
```

## Shortest Path

### All Shortest Paths from Owned Principals to Tier 0

```cypher
MATCH p = allShortestPaths((u:User)-[:AbuseTGTDelegation|AllowedToDelegate|HasSIDHistory|ADCSESC1|CanPSRemote|HasSession|ADCSESC10a|CanRDP|MemberOf|ADCSESC10b|CoerceAndRelayNTLMToADCS|Owns|ADCSESC13|CoerceAndRelayNTLMToLDAP|OwnsLimitedRights|ADCSESC3|CoerceAndRelayNTLMToLDAPS|ReadGMSAPassword|ADCSESC4|CoerceAndRelayNTLMToSMB|ReadLAPSPassword|ADCSESC6a|CoerceToTGT|SameForestTrust|ADCSESC6b|Contains|SpoofSIDHistory|ADCSESC9a|DCFor|SQLAdmin|ADCSESC9b|DCSync|SyncedToEntraUser|AddAllowedToAct|DumpSMSAPassword|SyncLAPSPassword|AddKeyCredentialLink|ExecuteDCOM|WriteAccountRestrictions|AddMember|ForceChangePassword|WriteDacl|AddSelf|GPLink|WriteGPLink|AdminTo|GenericAll|WriteOwner|AllExtendedRights|GenericWrite|WriteOwnerLimitedRights|AllowedToAct|GoldenCert|WriteSPN*1..]->(b:Base))
WHERE "owned" IN split(u.system_tags, " ")
  AND "admin_tier_0" IN split(b.system_tags, " ")
RETURN p
LIMIT 1000
```

- This query contains all traversable edges.

### All Shortest Paths from Low Privileged Groups to Tier 0

```cypher
UNWIND ['-S-1-5-11', '-S-1-5-32-554', '-S-1-1-0', '-513', '-S-1-5-32-545'] AS group
MATCH p = allShortestPaths((g:Group)-[:AbuseTGTDelegation|AllowedToDelegate|HasSIDHistory|ADCSESC1|CanPSRemote|HasSession|ADCSESC10a|CanRDP|MemberOf|ADCSESC10b|CoerceAndRelayNTLMToADCS|Owns|ADCSESC13|CoerceAndRelayNTLMToLDAP|OwnsLimitedRights|ADCSESC3|CoerceAndRelayNTLMToLDAPS|ReadGMSAPassword|ADCSESC4|CoerceAndRelayNTLMToSMB|ReadLAPSPassword|ADCSESC6a|CoerceToTGT|SameForestTrust|ADCSESC6b|Contains|SpoofSIDHistory|ADCSESC9a|DCFor|SQLAdmin|ADCSESC9b|DCSync|SyncedToEntraUser|AddAllowedToAct|DumpSMSAPassword|SyncLAPSPassword|AddKeyCredentialLink|ExecuteDCOM|WriteAccountRestrictions|AddMember|ForceChangePassword|WriteDacl|AddSelf|GPLink|WriteGPLink|AdminTo|GenericAll|WriteOwner|AllExtendedRights|GenericWrite|WriteOwnerLimitedRights|AllowedToAct|GoldenCert|WriteSPN*1..]->(b:Base))
WHERE g <> b
  AND g.objectid ENDS WITH group
  AND "admin_tier_0" IN split(b.system_tags, " ")
RETURN p
LIMIT 1000
```

- This query contains all traversable edges.

Used group SIDs:

- `-S-1-5-11`: Authenticated Users
- `-S-1-5-32-554`: Pre-Windows 2000 Compatible Access
- `-S-1-1-0`: Everyone
- `-513`: Domain Users
- `-S-1-5-32-545`: Users

### All Shortest Paths to Tier 0

```cypher
MATCH p = allShortestPaths((b1:Base)-[:AbuseTGTDelegation|AllowedToDelegate|HasSIDHistory|ADCSESC1|CanPSRemote|HasSession|ADCSESC10a|CanRDP|MemberOf|ADCSESC10b|CoerceAndRelayNTLMToADCS|Owns|ADCSESC13|CoerceAndRelayNTLMToLDAP|OwnsLimitedRights|ADCSESC3|CoerceAndRelayNTLMToLDAPS|ReadGMSAPassword|ADCSESC4|CoerceAndRelayNTLMToSMB|ReadLAPSPassword|ADCSESC6a|CoerceToTGT|SameForestTrust|ADCSESC6b|Contains|SpoofSIDHistory|ADCSESC9a|DCFor|SQLAdmin|ADCSESC9b|DCSync|SyncedToEntraUser|AddAllowedToAct|DumpSMSAPassword|SyncLAPSPassword|AddKeyCredentialLink|ExecuteDCOM|WriteAccountRestrictions|AddMember|ForceChangePassword|WriteDacl|AddSelf|GPLink|WriteGPLink|AdminTo|GenericAll|WriteOwner|AllExtendedRights|GenericWrite|WriteOwnerLimitedRights|AllowedToAct|GoldenCert|WriteSPN*1..]->(b2:Base))
WHERE b1 <> b2
  AND "admin_tier_0" IN split(b2.system_tags, " ")
RETURN p
LIMIT 1000
```

- This query contains all traversable edges.

### All Shortest Paths From Specific Account to Computers or Users (Adjust Query)

```cypher
WITH "alice" AS samaccountname
UNWIND ['Computer', 'User'] AS type
MATCH p = allShortestPaths((u:User)-[:AbuseTGTDelegation|AllowedToDelegate|HasSIDHistory|ADCSESC1|CanPSRemote|HasSession|ADCSESC10a|CanRDP|MemberOf|ADCSESC10b|CoerceAndRelayNTLMToADCS|Owns|ADCSESC13|CoerceAndRelayNTLMToLDAP|OwnsLimitedRights|ADCSESC3|CoerceAndRelayNTLMToLDAPS|ReadGMSAPassword|ADCSESC4|CoerceAndRelayNTLMToSMB|ReadLAPSPassword|ADCSESC6a|CoerceToTGT|SameForestTrust|ADCSESC6b|Contains|SpoofSIDHistory|ADCSESC9a|DCFor|SQLAdmin|ADCSESC9b|DCSync|SyncedToEntraUser|AddAllowedToAct|DumpSMSAPassword|SyncLAPSPassword|AddKeyCredentialLink|ExecuteDCOM|WriteAccountRestrictions|AddMember|ForceChangePassword|WriteDacl|AddSelf|GPLink|WriteGPLink|AdminTo|GenericAll|WriteOwner|AllExtendedRights|GenericWrite|WriteOwnerLimitedRights|AllowedToAct|GoldenCert|WriteSPN*1..]->(b:Base))
WHERE u <> b
  AND toLower(u.samaccountname) = toLower(samaccountname)
  AND (type IN LABELS(u))
RETURN p
LIMIT 1000
```

- This query contains all traversable edges.

### All Shortest Paths From Specific Account to Tier 0

```cypher
WITH "alice" AS samaccountname
MATCH p = allShortestPaths((u:User)-[:AbuseTGTDelegation|AllowedToDelegate|HasSIDHistory|ADCSESC1|CanPSRemote|HasSession|ADCSESC10a|CanRDP|MemberOf|ADCSESC10b|CoerceAndRelayNTLMToADCS|Owns|ADCSESC13|CoerceAndRelayNTLMToLDAP|OwnsLimitedRights|ADCSESC3|CoerceAndRelayNTLMToLDAPS|ReadGMSAPassword|ADCSESC4|CoerceAndRelayNTLMToSMB|ReadLAPSPassword|ADCSESC6a|CoerceToTGT|SameForestTrust|ADCSESC6b|Contains|SpoofSIDHistory|ADCSESC9a|DCFor|SQLAdmin|ADCSESC9b|DCSync|SyncedToEntraUser|AddAllowedToAct|DumpSMSAPassword|SyncLAPSPassword|AddKeyCredentialLink|ExecuteDCOM|WriteAccountRestrictions|AddMember|ForceChangePassword|WriteDacl|AddSelf|GPLink|WriteGPLink|AdminTo|GenericAll|WriteOwner|AllExtendedRights|GenericWrite|WriteOwnerLimitedRights|AllowedToAct|GoldenCert|WriteSPN*1..]->(b:Base))
WHERE u <> b
  AND toLower(u.samaccountname) = toLower(samaccountname)
  AND "admin_tier_0" IN split(b.system_tags, " ")
RETURN p
LIMIT 1000
```

- This query contains all traversable edges.

### Shortest Paths to Domain (including Computers)

```cypher
MATCH p = allShortestPaths((b)-[*1..]->(:Domain))
WHERE (b:User OR b:Computer)
RETURN p
LIMIT 1000
```

### Shortest Paths to no LAPS

```cypher
MATCH p = allShortestPaths((b)-[*1..]->(c:Computer))
WHERE b <> c
  AND (b:User OR b:Computer)
  AND c.haslaps = false
RETURN p
LIMIT 1000
```

### Shortest Paths from Owned Principals (including everything)

```cypher
MATCH p = allShortestPaths((u:User)-[*1..]->(b))
WHERE u <> b
  AND "owned" IN split(u.system_tags, " ")
RETURN p
LIMIT 1000
```

### Shortest Paths from Owned Principals to Domain

```cypher
MATCH p = allShortestPaths((b)-[*1..]->(:Domain))
WHERE "owned" IN split(b.system_tags, " ")
RETURN p
LIMIT 1000
```

### Shortest Paths from Owned Principals to High Value Targets

```cypher
MATCH p = allShortestPaths((b1)-[*1..]->(b2))
WHERE "owned" IN split(b1.system_tags, " ")
  AND "admin_tier_0" IN split(b2.system_tags, " ")
RETURN p
LIMIT 1000
```

### Shortest Paths from Owned Principals to no LAPS

```cypher
MATCH p = allShortestPaths((b)-[*1..]->(c:Computer {haslaps: false}))
WHERE b <> c
  AND "owned" IN split(b.system_tags, " ")
RETURN p
LIMIT 1000
```

### Shortest Paths from Domain Users and Domain Computers (including everything)

```cypher
MATCH p = allShortestPaths((g:Group)-[*1..]->(b))
WHERE g <> b
  AND (g.objectid =~ "(?i).*S-1-5-.*-513" OR g.objectid =~ "(?i).*S-1-5-.*-515")
RETURN p
LIMIT 1000
```

### Shortest Paths from no Signing to Domain

- Requires Set HasNoSMBSigning Members

```cypher
MATCH p = allShortestPaths((c:Computer)-[*1..]->(:Domain))
WHERE "hasnosmbsigning" IN split(c.user_tags, " ")
RETURN p
LIMIT 1000
```

### Shortest Paths from no Signing to High Value Targets

- Requires Set HasNoSMBSigning Members

```cypher
MATCH p = allShortestPaths((c:Computer)-[*1..]->(b))
WHERE c <> b
  AND "hasnosmbsigning" IN split(c.user_tags, " ")
  AND "admin_tier_0" IN split(b.system_tags, " ")
RETURN p
LIMIT 1000
```

### Shortest Paths from WebClientService Clients to Tier 0

```cypher
MATCH p = allShortestPaths((c:Computer)-[:AbuseTGTDelegation|AllowedToDelegate|HasSIDHistory|ADCSESC1|CanPSRemote|HasSession|ADCSESC10a|CanRDP|MemberOf|ADCSESC10b|CoerceAndRelayNTLMToADCS|Owns|ADCSESC13|CoerceAndRelayNTLMToLDAP|OwnsLimitedRights|ADCSESC3|CoerceAndRelayNTLMToLDAPS|ReadGMSAPassword|ADCSESC4|CoerceAndRelayNTLMToSMB|ReadLAPSPassword|ADCSESC6a|CoerceToTGT|SameForestTrust|ADCSESC6b|Contains|SpoofSIDHistory|ADCSESC9a|DCFor|SQLAdmin|ADCSESC9b|DCSync|SyncedToEntraUser|AddAllowedToAct|DumpSMSAPassword|SyncLAPSPassword|AddKeyCredentialLink|ExecuteDCOM|WriteAccountRestrictions|AddMember|ForceChangePassword|WriteDacl|AddSelf|GPLink|WriteGPLink|AdminTo|GenericAll|WriteOwner|AllExtendedRights|GenericWrite|WriteOwnerLimitedRights|AllowedToAct|GoldenCert|WriteSPN*1..]->(b2))
WHERE "admin_tier_0" IN split(b2.system_tags, " ")
  AND c.webclientrunning = True
RETURN p
LIMIT 1000
```
- This query contains all traversable edges.

## DACL Abuse

### LAPS Passwords Readable by Non-Admin

```cypher
MATCH p = (b:Base)-[:AllExtendedRights|ReadLAPSPassword|GenericAll]->(:Computer {haslaps:true})
WHERE NOT "admin_tier_0" IN split(b.system_tags, " ") OR b.system_tags is NULL
RETURN p
LIMIT 1000
```

### LAPS Passwords Readable by Owned Principals

```cypher
MATCH p = (u)-[:MemberOf*1..]->(:Group)-[:GenericAll]->(t:Computer {haslaps:true})
WHERE "owned" IN split(u.system_tags, " ")
RETURN p
LIMIT 1000
```

### ACLs to Computers (excluding High Value Targets)

```cypher
MATCH p = (b)-[{isacl: true}]->(:Computer)
WHERE (b:User OR b:Computer OR b:Group)
  AND (NOT "admin_tier_0" IN split(b.system_tags, " ") OR b.system_tags is NULL)
RETURN p
LIMIT 1000
```

### Group Delegated Outbound Object Control from Owned Principals

```cypher
MATCH p = (b1)-[:MemberOf*1..]->(:Group)-[{isacl: true}]->(b2)
WHERE "owned" IN split(b1.system_tags, " ")
RETURN p
LIMIT 1000
```

### Dangerous Rights for Groups under Domain Users

```cypher
UNWIND ['-S-1-5-11', '-S-1-5-32-554', '-S-1-1-0', '-513', '-S-1-5-32-545'] AS group
MATCH p = (g:Group)-[:MemberOf*1..]->(:Group)-[:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword]->(b)
WHERE g.objectid ENDS WITH group
RETURN p
LIMIT 1000
```

Used group SIDs:

- `-S-1-5-11`: Authenticated Users
- `-S-1-5-32-554`: Pre-Windows 2000 Compatible Access
- `-S-1-1-0`: Everyone
- `-513`: Domain Users
- `-S-1-5-32-545`: Users

### dMSA Accounts Controlled by Non-Tier 0 (BadSuccessor)

```cypher
MATCH p = (d:Computer)<-[:WriteDacl|Owns|GenericAll|GenericWrite|WriteOwner]-(n:Base)
WHERE d.`msds-delegatedmsastate` IS NOT NULL
  AND (NOT "admin_tier_0" IN split(n.system_tags, " ") OR n.system_tags is NULL)
RETURN p
LIMIT 1000
```

Remember, this requires `--collectallproperties` of SharpHound!

## GPOs

### Interesting GPOs by Keyword

```cypher
UNWIND ["360totalsecurity", "access", "acronis", "adaware", "admin", "admin", "aegislab", "ahnlab", "alienvault", "altavista", "amsi", "anti-virus", "antivirus", "antiy", "apexone", "applock", "arcabit", "arcsight", "atm", "atp", "av", "avast", "avg", "avira", "baidu", "baiduspider", "bank", "barracuda", "bingbot", "bitdefender", "bluvector", "canary", "carbon", "carbonblack", "certificate", "check", "checkpoint", "citrix", "clamav", "code42", "comodo", "countercept", "countertack", "credential", "crowdstrike", "custom", "cyberark", "cybereason", "cylance", "cynet360", "cyren", "darktrace", "datadog", "defender", "druva", "drweb", "duckduckbot", "edr", "egambit", "emsisoft", "encase", "endgame", "ensilo", "escan", "eset", "exabot", "exception", "f-secure", "f5", "falcon", "fidelis", "fireeye", "firewall", "fix", "forcepoint", "forti", "fortigate", "fortil", "fortinet", "gdata", "gravityzone", "guard", "honey", "huntress", "identity", "ikarussecurity", "insight", "ivanti", "juniper", "k7antivirus", "k7computing", "kaspersky", "kingsoft", "kiosk", "laps", "lightcyber", "logging", "logrhythm", "lynx", "malwarebytes", "manageengine", "mass", "mcafee", "microsoft", "mj12bot", "msnbot", "nanoav", "nessus", "netwitness", "office365", "onedrive", "orion", "palo", "paloalto", "paloaltonetworks", "panda", "pass", "powershell", "proofpoint", "proxy", "qradar", "rdp", "rsa", "runasppl", "sandbox", "sap", "scanner", "scanning", "sccm", "script", "secret", "secureage", "secureworks", "security", "sensitive", "sentinel", "sentinelone", "slurp", "smartcard", "sogou", "solarwinds", "sonicwall", "sophos", "splunk", "superantispyware", "symantec", "tachyon", "temporary", "tencent", "totaldefense", "transfer", "trapmine", "trend micro", "trendmicro", "trusteer", "trustlook", "uac", "vdi", "virusblokada", "virustotal", "virustotalcloud", "vpn", "vuln", "webroot", "whitelist", "wifi", "winrm", "workaround", "yubikey", "zillya", "zonealarm", "zscaler"] as word
MATCH p = (g:GPO)-[:GPLink*1..]->(:Base)
WHERE toLower(g.name) CONTAINS toLower(word)
RETURN p
LIMIT 1000
```

### GPO Permissions of Non-Admin Principals

```cypher
MATCH p = (u:User)-[:AddMember|AddSelf|WriteSPN|AddKeyCredentialLink|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(:GPO)
WHERE NOT 'admin_tier_0' IN split(u.system_tags, ' ') OR u.system_tags is NULL
RETURN p
LIMIT 1000
```

## ADCS

### All CAs

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:EnterpriseCA)
RETURN p
LIMIT 1000
```

### All Certificate Templates

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(n:CertTemplate)
RETURN p
LIMIT 1000
```

### All Published Templates

```cypher
MATCH p = (ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
RETURN p
LIMIT 1000
```

### ESC1/3/4/14 not from Tier-0

```cypher
MATCH p = (b)-[:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC13]->()
WHERE NOT "admin_tier_0" IN split(b.system_tags, " ") OR b.system_tags is NULL
RETURN p
LIMIT 1000
```

### ESC15 (EKUwu)

- Note: Probably patched so false positives will happen.

```cypher
MATCH p = (:Base)-[:Enroll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)-[:TrustedForNTAuth]->(:NTAuthStore)-[:NTAuthStoreFor]->(:Domain)
WHERE ct.enrolleesuppliessubject = True
  AND ct.authenticationenabled = False
  AND ct.requiresmanagerapproval = False
  AND ct.schemaversion = 1
RETURN p
LIMIT 1000
```

- Query Source: Twitter [@SpecterOps](https://x.com/SpecterOps/status/1844800558151901639)
- More information: https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc


# BloodHound Operator Custom Queries

## On-Prem

### Set Server Operators, Account Operators and Print Operators as High Value Targets

These groups were included as high value targets in the old BH.

```powershell
$TierZero = BHNodeGroup | ? name -eq 'Admin Tier Zero'
BHPath "MATCH (g:Group) WHERE (g.system_tags IS NULL OR NOT 'admin_tier_0' IN split(g.system_tags, ' ')) AND (g.objectid =~ '(?i).*S-1-5-.*-548' OR g.objectid =~ '(?i).*S-1-5-.*-549' OR g.objectid =~ '(?i).*S-1-5-.*-550') RETURN g" | Add-BHNodeToNodeGroup -NodeGroupID $TierZero.id -force
```

### Set DCSync Principals as High Value Targets

```powershell
$TierZero = BHNodeGroup | ? name -eq 'Admin Tier Zero'
BHPath "MATCH (n)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain) WHERE (n.system_tags IS NULL OR NOT 'admin_tier_0' IN split(n.system_tags, ' ')) RETURN n" | Add-BHNodeToNodeGroup -NodeGroupID $TierZero.id -force
```

### Set DCSync Principals as High Value Targets with GetChanges and GetChangesAll Edges

This query is probably not necessary as BloodHound will create the abusable edge DCSync if GetChanges and GetChangesAll are given.

```powershell
$TierZero = BHNodeGroup | ? name -eq 'Admin Tier Zero'
BHPath "MATCH (n)-[:DCSync|AllExtendedRights|GenericAll|GetChanges|GetChangesAll]->(:Domain) WHERE (n.system_tags IS NULL OR NOT 'admin_tier_0' IN split(n.system_tags, ' ')) RETURN n" | Add-BHNodeToNodeGroup -NodeGroupID $TierZero.id -force
```

### Set Unconstrained Delegation Principals as High Value Targets

```powershell
$TierZero = BHNodeGroup | ? name -eq 'Admin Tier Zero'
BHPath "MATCH (n) WHERE (n:User OR n:Computer) AND n.unconstraineddelegation = true AND (n.system_tags IS NULL OR NOT 'admin_tier_0' IN split(n.system_tags, ' ')) RETURN n" | Add-BHNodeToNodeGroup -NodeGroupID $TierZero.id -force
```

### Set Local Admin or Reset Password Principals as High Value Targets

```powershell
$TierZero = BHNodeGroup | ? name -eq 'Admin Tier Zero'
BHPath "MATCH (n)-[:AdminTo|ForceChangePassword]->(b) WHERE (n.system_tags IS NULL OR NOT 'admin_tier_0' IN split(n.system_tags, ' ')) RETURN n" | Add-BHNodeToNodeGroup -NodeGroupID $TierZero.id -force
```

### Set Principals with Privileges on Computers as High Value Targets

```powershell
$TierZero = BHNodeGroup | ? name -eq 'Admin Tier Zero'
BHPath "MATCH (n)-[:AllowedToDelegate|ExecuteDCOM|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner]->(:Computer) WHERE (n.system_tags IS NULL OR NOT 'admin_tier_0' IN split(n.system_tags, ' ')) RETURN n" | Add-BHNodeToNodeGroup -NodeGroupID $TierZero.id -force
```

### Set Principals with Privileges on Cert Publishers as High Value Target

```powershell
$TierZero = BHNodeGroup | ? name -eq 'Admin Tier Zero'
BHPath "MATCH (n)-[:GenericAll|GenericWrite|MemberOf|Owns|WriteDacl|WriteOwner]->(g:Group) WHERE g.objectid =~ '(?i).*S-1-5-21-.*-517' AND (n.system_tags IS NULL OR NOT 'admin_tier_0' IN split(n.system_tags, ' ')) RETURN n" | Add-BHNodeToNodeGroup -NodeGroupID $TierZero.id -force
```

### Set Members of High Value Targets Groups as High Value Targets

```powershell
$TierZero = BHNodeGroup | ? name -eq 'Admin Tier Zero'
BHPath "MATCH (n)-[:MemberOf*1..]->(g:Group) WHERE (n.system_tags IS NULL OR NOT 'admin_tier_0' IN split(n.system_tags, ' ')) AND g.system_tags CONTAINS 'admin_tier_0' RETURN n" | Add-BHNodeToNodeGroup -NodeGroupID $TierZero.id -force
```

### Set HasNoSMBSigning Members

This creates a user Node Group called HasNoSMBSigning. Provide a file with computer names like "pc1.domain.local". One entry per line.

```powershell
New-BHNodeGroup HasNoSMBSigning
$HasNoSMBSigning = BHNodeGroup | ? name -eq 'HasNoSMBSigning'
foreach($line in [System.IO.File]::ReadLines("./no-smb-computers.txt"))
{
       BHSearch Computer $line | Add-BHNodeToNodeGroup -NodeGroupID $HasNoSMBSigning.id -force
}
```

### Remove Inactive Users and Computers from High Value Targets

Inactive = last logon > 180 days.

```powershell
$TierZero = BHNodeGroup | ? name -eq 'Admin Tier Zero'
BHPath "MATCH (uc) WHERE uc.system_tags CONTAINS 'admin_tier_0' AND ((uc:User AND uc.enabled = false) OR (uc:Computer AND ((uc.enabled = false) OR (uc.lastlogon > 0 AND uc.lastlogon < (TIMESTAMP() / 1000 - 15552000)) OR (uc.lastlogontimestamp > 0 AND uc.lastlogontimestamp < (TIMESTAMP() / 1000 - 15552000))))) RETURN uc" | Remove-BHNodeFromNodeGroup -NodeGroupID $TierZero.id -force
```


## Get Inactive or Decommissioned Machines:

- Retrieves all computers where the last logon occurred before a specified year.
- Useful for querying computer objects that exist in the AD domain but have not logged on for a long time.
- This helps in identifying potentially inactive or decommissioned machines.

```cypher
MATCH (c:Computer)
WHERE c.lastlogon IS NOT NULL
AND datetime({epochMillis: toInteger(c.lastlogon * 1000)}).year < 2010
RETURN *
```

## Get All Domain Controllers:

- Retrieves all Domain Controllers

```cypher
MATCH (c:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' RETURN c
```

## Get All  Unconstrained Delegation Computers That are Not Domain Controllers:

- Retrieves all computers that allow unconstrained delegation but are not domain controllers.

```cypher 
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectsid ENDS WITH '-516' WITH COLLECT(c1.name) AS domainControllers
MATCH (c2:Computer {unconstraineddelegation:true}) WHERE NOT c2.name IN domainControllers RETURN c2
```

## Query for Users with Password Last Set in Year X:

- Identify user accounts where the password was last set in the year 2009. It is specifically useful for auditing security practices related to password management policies and identifying potentially dormant or neglected accounts in the Active Directory environment.

```cypher 
MATCH (u:User)
WHERE u.pwdlastset IS NOT NULL
AND datetime({epochMillis: toInteger(u.pwdlastset * 1000)}).year = $YEAR_X
RETURN *

// EXAMPLE
MATCH (u:User)
WHERE u.pwdlastset IS NOT NULL
AND datetime({epochMillis: toInteger(u.pwdlastset * 1000)}).year = 2009
RETURN *
```

## Query to identify AS-REP Roastable users with passwords set 10 or more years ago and passwords that never expire:

- Retrieves all users who are susceptible to AS-REP Roasting, have passwords that never expire, and whose passwords were set 10 or more years ago.

```cypher
MATCH (u:User {dontreqpreauth: true})
WHERE u.pwdlastset IS NOT NULL 
AND u.pwdneverexpires = true
AND datetime({epochMillis: toInteger(u.pwdlastset * 1000)}).year <= (datetime().year - 10)
RETURN *
```

## Query to get all Kerberoastable users:

```cypher
MATCH (u:User {hasspn:true})
RETURN *
```

## Query to identify Kerberoastable users with passwords set 10 or more years ago and passwords that never expire:

- Retrieves all users who are susceptible to Kerberoasting, have passwords that never expire, and whose passwords were set 10 or more years ago.

```cypher
MATCH (u:User {hasspn:true})
WHERE u.pwdlastset IS NOT NULL 
AND u.pwdneverexpires = true
AND datetime({epochMillis: toInteger(u.pwdlastset * 1000)}).year <= (datetime().year - 10)
RETURN *
```

## Admin Rights and Non-admin Accounts
Improper allocation of administrative rights through naming convention analysis within an organization. 
```cypher
MATCH p=(m:User)-[r:AdminTo]->(n:Computer)
WHERE NOT m.name CONTAINS “.helpdesk”
RETURN m
```

## External Domains and Nested Group Memberships in Tier Zero
Shows instances where bi-directional trust dramatically increases Tier Zero and expands the potential for undesirable Attack Paths within a forest. 
    - Identify Tier Zero groups that exist in a particular domain
    - Identify nesting under another Tier Zero group in a separate domain within a forest
```cypher
MATCH p=((n:Group)-[:MemberOf*..]->(t:Group))
WHERE n.domainsid <> t.domainsid AND coalesce(n.system_tags,"") CONTAINS ('tier_0') AND coalesce(t.system_tags,"") CONTAINS ('tier_0')
AND NOT n.objectid ENDS WITH "-512"
AND NOT n.objectid ENDS WITH "-519"
RETURN p
```