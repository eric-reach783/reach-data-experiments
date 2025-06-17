
Inclusion of MITRE data:
- Mapped MITRE ATT&CK Tactics to OU nodes for visualization in BloodHound.
- Identify attack paths (how an attacker could move from one user to another).
- Map your environment to ATT&CK techniques for threat hunting and defense.

- Scripts:
- scripts/ATTCKnowledge-push.py

### Validate MITRE ingest using cypher queries:

#### Tactics Validation (OU Nodes)
Maps TA (tactics) to OU nodes (containers, uses, groups, computers, and other OUs).
```cypher
MATCH (n:OU)
WHERE n.id STARTS WITH 'TA'
RETURN count(n) AS TacticCount, 
       n.id AS SampleID, 
       n.name AS SampleName
LIMIT 5
```

#### Techniques Validation (GPO Nodes)

```cypher
MATCH (n:GPO)
WHERE n.id STARTS WITH 'T'
RETURN labels(n) AS NodeType, 
       count(n) AS TechniqueCount, 
       n.tactic AS FirstTacticAssociation
```

#### Tactic-Technique Association
```cypher
MATCH (t:GPO)-[r:USES]->(a:OU)
RETURN t.name AS Technique, 
       a.name AS Tactic, 
       type(r) AS RelationshipType
LIMIT 10
```

#### Group-Software Relationships
```cypher
MATCH (g:Group)-[r]->(s:Computer)
WHERE r.edge = 'uses'
RETURN g.name AS ThreatGroup, 
       s.name AS Malware, 
       count(r) AS UsageCount
```

#### STIX ID Consistency Check
```cypher
MATCH (n)
WHERE n.stix IS NOT NULL
RETURN DISTINCT labels(n)[0] AS NodeType, 
       count(n.stix) AS STIXPopulatedCount, 
       all(id IN n.stix WHERE id CONTAINS 'attack-pattern') AS ValidSTIXFormat
```

#### MITRE Wiki Link Verification
```cypher
MATCH (n)
WHERE n.wiki IS NOT NULL
RETURN n.name AS EntityName, 
       n.wiki AS WikiURL, 
       HEAD(SPLIT(n.wiki, '/')) AS DomainVerified
```

#### Label Distribution Analysis
```cypher
CALL db.labels() YIELD label
MATCH (n)
WHERE label IN labels(n)
RETURN label AS NodeType, 
       count(n) AS NodeCount, 
       keys(n) AS CommonProperties
ORDER BY NodeCount DESC

```

#### Relationship Type Audit
The query above is a database introspection query that tells you:

    What types of relationships exist in your BloodHound graph (e.g., how users are connected to groups, who has admin rights, who is logged on where).

    How many relationships there are of each type.

    What properties are stored on those relationships (if any).


The relationships in BloodHound (like AdminTo, HasSession, MemberOf) directly map to ATT&CK techniques for privilege escalation, lateral movement, and persistence.

    Example:

        AdminTo → Privilege Escalation (T1078, T1098)

        HasSession → Lateral Movement (T1078, T1021)

        MemberOf → Group Discovery (T1069), Account Discovery (T1087)

_Does not work in the BH UI (use neo4j UI)_
```cypher
CALL db.relationshipTypes() YIELD relationshipType
MATCH ()-[r]->()
WHERE type(r) = relationshipType
RETURN relationshipType, 
       count(r) AS RelationshipCount, 
       HEAD(keys(r)) AS SampleProperty
```

#### MITRE ID Cross-Reference
Not working
```cypher
MATCH (n)
WHERE n.id IS NOT NULL
WITH n.id AS MITRE_ID, labels(n)[0] AS Type
RETURN Type, 
       count(MITRE_ID) AS TotalIDs, 
       apoc.coll.frequency(COLLECT(MITRE_ID), MITRE_ID) AS DuplicateCheck
```

#### Data Freshness Verification
```cypher
MATCH (n)
WHERE n:UPDATE_TIMESTAMP
RETURN n.last_updated AS LastImportDate, 
       datetime().year - n.last_updated.year AS YearsSinceUpdate
```

#### Orphaned Node Detection
```cypher
MATCH (n)
WHERE NOT (n)--()
RETURN labels(n) AS IsolatedNodeType, 
       count(n) AS OrphanCount, 
       COLLECT(n.name)[0..5] AS SampleEntities
```

#### Property Completeness Audit
```cypher
MATCH (n)
WITH labels(n)[0] AS NodeType, 
     keys(n) AS Properties
RETURN NodeType, 
       size(Properties) AS PropertyCount, 
       apoc.coll.contains(Properties, 'wiki') AS HasWikiLink
```

#### Find All BloodHound AD Nodes and Their Types
```cypher
MATCH (n)
WHERE 
  (n:User OR n:Group OR n:Computer OR n:Domain OR n:OU OR n:GPO)
  AND n.objectid IS NOT NULL 
  AND n.objectid <> "null"
RETURN labels(n) AS type, n.name, n.objectid, n.description
LIMIT 100;
```

#### Tier 1: BloodHound ADier Management Selectors
DCs, high-value groups, users with direct admin rights.
```cypher
MATCH (n)
WHERE (n:Computer AND n.name CONTAINS 'DC') OR
      (n:Group AND n.highvalue = true) OR
      (n:User AND n.admincount = true)
RETURN n.name AS name, labels(n) AS type, "Tier 1" AS tier
```

#### Tier 2: Sensitive Assets
```cypher
MATCH (n)
WHERE
  (n:Computer
    AND EXISTS {
      (n)<-[:HasSession]-(:User {admincount: true})
    })
  OR (n:User
    AND EXISTS {
      (n)-[:MemberOf]->(:Group {highvalue: true})
    })
  OR (n:User
    AND n.serviceprincipalname IS NOT NULL)
RETURN
  n.name AS name,
  labels(n) AS type,
  "Tier 2" AS tier;
```

#### Tier 3: Standard Assets
```cypher
MATCH (n)
WHERE NOT (
    (n:Computer AND n.name CONTAINS 'DC') OR
    (n:Group AND n.highvalue = true) OR
    (n:User AND n.admincount = true) OR
    (n:Computer AND EXISTS((n)<-[:HasSession]-(:User {admincount: true}))) OR
    (n:User WHERE EXISTS((n)-[:MemberOf]->(:Group {highvalue: true}))) OR
    (n:User AND n.serviceprincipalname IS NOT NULL)
)
RETURN n.name AS name, labels(n) AS type, "Tier 3" AS tier
```


#### Combined Bloodhound & MITRE TTP Visual Graph
To visualize both Bloodhound AD nodes and MITRE TTPs together in a single graph, use this query:
```cypher
MATCH (n)
WHERE (n:Computer OR n:Group OR n:User OR n:Technique OR n:Tactic)
OPTIONAL MATCH (n)-[r]-(m)
RETURN n, r, m
```

#### Attack Path with MITRE TTPs
To visualize an attack path from a user to a high-value group, including MITRE techniques and tactics:
```cypher
MATCH path=(u:User)-[*1..5]->(g:Group {highvalue: true})
OPTIONAL MATCH (u)-[:USES_TECHNIQUE|USES_TACTIC]->(t)
RETURN path, u, g, t
```



Using thses two powershell files, convert them to python3.11.
- https://github.com/SadProcessor/SomeStuff/blob/master/DerbyCon19/ATTCKnowledge.ps1
- https://github.com/SadProcessor/SomeStuff/blob/master/PushToBH.ps1
- https://github.com/SadProcessor/SomeStuff/blob/master/CypherDog15_Alpha3.ps1
Verify that every class, object, and variable from the powershell scripts exists, validate that the function and
tool calls exist and document the conversion in code comments. Combine these scripts into one, they must make sense logically and follow
the workflow in the following link: https://medium.com/falconforce/graphing-mitre-att-ck-via-bloodhound-87c11aadc119
