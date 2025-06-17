
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