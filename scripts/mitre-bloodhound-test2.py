"""
Combined ATT&CK Knowledge, CypherDog, and PushToBH functionality in Python 3.11
- Fetches and parses MITRE ATT&CK data from GitHub
- Maps techniques, tactics, groups, and software to BloodHound/Neo4j schema
- Pushes relationships to a Neo4j instance
- Follows workflow from: https://medium.com/falconforce/graphing-mitre-att-ck-via-bloodhound-87c11aadc119

Requires:
    requests
    neo4j (pip install neo4j)
"""

import requests
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from neo4j import GraphDatabase

# =========================
# === Data Model Classes ==
# =========================

class ATTCKTactic:
    def __init__(self, name, description, type_, id_, wiki, reference, created, modified, contributor, stix):
        self.name = name
        self.description = description
        self.type = type_
        self.id = id_
        self.wiki = wiki
        self.reference = reference
        self.created = created
        self.modified = modified
        self.contributor = contributor
        self.stix = stix

class ATTCKTechnique:
    def __init__(self, name, tactic, description, platform, permission, bypass, effective_perm,
                 network, remote, prereq, detection, mitigation, data_source, id_, wiki,
                 reference, created, modified, contributor, stix):
        self.name = name
        self.tactic = tactic
        self.description = description
        self.platform = platform
        self.permission = permission
        self.bypass = bypass
        self.effective_perm = effective_perm
        self.network = network
        self.remote = remote
        self.prereq = prereq
        self.detection = detection
        self.mitigation = mitigation
        self.data_source = data_source
        self.id = id_
        self.wiki = wiki
        self.reference = reference
        self.created = created
        self.modified = modified
        self.contributor = contributor
        self.stix = stix

class ATTCKGroup:
    def __init__(self, name, description, alias, id_, wiki, reference, created, modified, contributor, stix):
        self.name = name
        self.description = description
        self.alias = alias
        self.id = id_
        self.wiki = wiki
        self.reference = reference
        self.created = created
        self.modified = modified
        self.contributor = contributor
        self.stix = stix

class ATTCKSoftware:
    def __init__(self, name, description, type_, alias, id_, wiki, reference, created, modified, contributor, stix):
        self.name = name
        self.description = description
        self.type = type_
        self.alias = alias
        self.id = id_
        self.wiki = wiki
        self.reference = reference
        self.created = created
        self.modified = modified
        self.contributor = contributor
        self.stix = stix

class ATTCKRelationship:
    def __init__(self, source, edge, target, description, reference):
        self.source = source
        self.edge = edge
        self.target = target
        self.description = description
        self.reference = reference

# ================================
# === Knowledge Fetch & Parsing ==
# ================================

class ATTCKnowledge:
    """
    Main knowledge object, holds all parsed ATT&CK data.
    """
    def __init__(self):
        self.tactic = []
        self.technique = []
        self.group = []
        self.software = []
        self.relationship = []

    def sync(self):
        """
        Fetches and parses ATT&CK Enterprise data from MITRE CTI GitHub.
        """
        print("[*] Fetching ATT&CK Enterprise data...")
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        resp = requests.get(url)
        resp.raise_for_status()
        data = resp.json()
        objects = data['objects']

        # Parse Tactics
        print("[*] Parsing Tactics...")
        for obj in filter(lambda o: o.get('type') == 'x-mitre-tactic', objects):
            self.tactic.append(ATTCKTactic(
                name=obj.get('name'),
                description=obj.get('description'),
                type_=obj.get('type'),
                id_=get_external_id(obj),
                wiki=get_external_url(obj),
                reference=get_references(obj),
                created=obj.get('created'),
                modified=obj.get('modified'),
                contributor=obj.get('x_mitre_contributors', []),
                stix=obj.get('id')
            ))

        # Parse Techniques
        print("[*] Parsing Techniques...")
        taclist = [o for o in objects if o.get('type') == 'course-of-action']
        for obj in filter(lambda o: o.get('type') == 'attack-pattern', objects):
            tech_name = obj.get('name')
            mitigation = next((t.get('description') for t in taclist if t.get('name') == tech_name), None)
            self.technique.append(ATTCKTechnique(
                name=tech_name,
                tactic=[phase.get('phase_name') for phase in obj.get('kill_chain_phases', [])] if obj.get('kill_chain_phases') else [],
                description=obj.get('description'),
                platform=obj.get('x_mitre_platforms', []),
                permission=obj.get('x_mitre_permissions_required', []),
                bypass=obj.get('x_mitre_defense_bypassed', []),
                effective_perm=obj.get('x_mitre_effective_permissions', []),
                network=obj.get('x_mitre_network_requirements'),
                remote=obj.get('x_mitre_remote_support'),
                prereq=obj.get('x_mitre_system_requirements'),
                detection=obj.get('x_mitre_detection'),
                mitigation=mitigation,
                data_source=obj.get('x_mitre_data_sources', []),
                id_=get_external_id(obj),
                wiki=get_external_url(obj),
                reference=get_references(obj),
                created=obj.get('created'),
                modified=obj.get('modified'),
                contributor=obj.get('x_mitre_contributors', []),
                stix=obj.get('id')
            ))

        # Parse Groups
        print("[*] Parsing Groups...")
        for obj in filter(lambda o: o.get('type') == 'intrusion-set', objects):
            self.group.append(ATTCKGroup(
                name=obj.get('name'),
                description=obj.get('description'),
                alias=obj.get('aliases', []),
                id_=get_external_id(obj),
                wiki=get_external_url(obj),
                reference=get_references(obj),
                created=obj.get('created'),
                modified=obj.get('modified'),
                contributor=obj.get('x_mitre_contributors', []),
                stix=obj.get('id')
            ))

        # Parse Software
        print("[*] Parsing Software...")
        for obj in filter(lambda o: o.get('type') in ['tool', 'malware'], objects):
            self.software.append(ATTCKSoftware(
                name=obj.get('name'),
                description=obj.get('description'),
                type_=obj.get('type'),
                alias=obj.get('x_mitre_aliases', []),
                id_=get_external_id(obj),
                wiki=get_external_url(obj),
                reference=get_references(obj),
                created=obj.get('created'),
                modified=obj.get('modified'),
                contributor=obj.get('x_mitre_contributors', []),
                stix=obj.get('id')
            ))

        # Parse Relationships
        print("[*] Parsing Relationships...")
        for obj in filter(lambda o: o.get('type') == 'relationship', objects):
            self.relationship.append(ATTCKRelationship(
                source=obj.get('source_ref'),
                edge=obj.get('relationship_type'),
                target=obj.get('target_ref'),
                description=obj.get('description'),
                reference=get_references(obj)
            ))

def get_external_id(obj):
    """Extracts the MITRE ATT&CK external_id from external_references."""
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('external_id')
    return None

def get_external_url(obj):
    """Extracts the MITRE ATT&CK URL from external_references."""
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('url')
    return None

def get_references(obj):
    """Returns all non-mitre-attack external references."""
    return [ref for ref in obj.get('external_references', []) if ref.get('source_name') != 'mitre-attack']

# ==============================
# === CypherDog (Mapping) ======
# ==============================

class CypherDog:
    """
    Maps ATT&CK objects to BloodHound/Neo4j Cypher queries.
    """
    def __init__(self, knowledge: ATTCKnowledge):
        self.knowledge = knowledge

    def generate_neo4j_queries(self):
        """
        Converts ATT&CK knowledge into Cypher queries for Neo4j.
        Returns a list of Cypher query strings.
        """
        queries = []

        # Create Tactic nodes
        for tactic in self.knowledge.tactic:
            queries.append(
                f"MERGE (t:Tactic {{id: '{tactic.id}'}}) "
                f"SET t.name = $name, t.description = $description"
            )

        # Create Technique nodes and relationships to Tactic
        for tech in self.knowledge.technique:
            queries.append(
                f"MERGE (tech:Technique {{id: '{tech.id}'}}) "
                f"SET tech.name = $name, tech.description = $description"
            )
            # Link to Tactic
            for tactic_name in tech.tactic:
                queries.append(
                    f"MATCH (t:Tactic), (tech:Technique) "
                    f"WHERE t.name = $tactic_name AND tech.id = '{tech.id}' "
                    f"MERGE (t)-[:USES]->(tech)"
                )

        # Create Group nodes
        for group in self.knowledge.group:
            queries.append(
                f"MERGE (g:Group {{id: '{group.id}'}}) "
                f"SET g.name = $name, g.description = $description"
            )

        # Create Software nodes
        for sw in self.knowledge.software:
            queries.append(
                f"MERGE (s:Software {{id: '{sw.id}'}}) "
                f"SET s.name = $name, s.description = $description"
            )

        # Create Relationships (Group/Software/Technique)
        for rel in self.knowledge.relationship:
            # This is a simplified mapping; in practice, you'd want to resolve source/target types
            queries.append(
                f"MATCH (a), (b) WHERE a.stix = '{rel.source}' AND b.stix = '{rel.target}' "
                f"MERGE (a)-[:{rel.edge.upper()}]->(b)"
            )
        return queries

# ===================================
# === PushToBH (Neo4j Integration) ==
# ===================================

class PushToBH:
    """
    Pushes Cypher queries to a Neo4j instance.
    """
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def push_queries(self, queries, params=None):
        with self.driver.session() as session:
            for query in queries:
                # Use parameters for safety, but for demo, we use string formatting
                session.run(query, params or {})

    def close(self):
        self.driver.close()

# ==========================
# === Main Workflow ========
# ==========================

def main():
    # 1. Sync ATT&CK Knowledge
    knowledge = ATTCKnowledge()
    knowledge.sync()

    # 2. Map to Cypher/BloodHound queries
    cypher_dog = CypherDog(knowledge)
    queries = cypher_dog.generate_neo4j_queries()

    # 3. Push to Neo4j (adjust connection details as needed)
    print("[*] Pushing to Neo4j...")
    neo4j_uri = "bolt://localhost:7687"
    neo4j_user = "neo4j"
    neo4j_pass = "your_password"
    pusher = PushToBH(neo4j_uri, neo4j_user, neo4j_pass)
    pusher.push_queries(queries)
    pusher.close()
    print("[*] Done.")

if __name__ == "__main__":
    main()
