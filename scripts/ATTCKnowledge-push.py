import requests
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from neo4j import GraphDatabase
import logging
import webbrowser

# --- Data Models (from ATTCKnowledge.ps1) ---

@dataclass
class ATTCKTactic:
    name: str
    description: str
    type: List[str]
    id: str
    wiki: str
    reference: Any
    created: str
    modified: str
    contributor: List[str]
    stix: str

@dataclass
class ATTCKTechnique:
    name: str
    tactic: List[str]
    description: str
    platform: List[str]
    permission: List[str]
    bypass: List[str]
    effective_perm: List[str]
    network: str
    remote: str
    prereq: str
    detection: str
    mitigation: str
    data_source: List[str]
    id: str
    wiki: str
    reference: Any
    created: str
    modified: str
    contributor: List[str]
    stix: str

@dataclass
class ATTCKSoftware:
    name: str
    description: str
    type: str
    alias: List[str]
    id: str
    wiki: str
    reference: Any
    created: str
    modified: str
    contributor: List[str]
    stix: str

@dataclass
class ATTCKGroup:
    name: str
    description: str
    alias: List[str]
    id: str
    wiki: str
    reference: Any
    created: str
    modified: str
    contributor: List[str]
    stix: str

@dataclass
class ATTCKRelationship:
    source: str
    edge: str
    target: str
    description: Optional[str] = ""
    reference: Optional[Any] = None

# --- ATTCKnowledge Loader (from ATTCKnowledge.ps1) ---

class ATTCKnowledge:
    def __init__(self):
        self.tactics: List[ATTCKTactic] = []
        self.techniques: List[ATTCKTechnique] = []
        self.software: List[ATTCKSoftware] = []
        self.groups: List[ATTCKGroup] = []
        self.relationships: List[ATTCKRelationship] = []

    def sync(self):
        # Download MITRE ATT&CK enterprise data
        url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        objects = data.get('objects', [])

        # Parse objects into data classes
        for obj in objects:
            if obj.get('type') == 'x-mitre-tactic':
                ext_ref = next((ref for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), {})
                self.tactics.append(ATTCKTactic(
                    name=obj.get('name', ''),
                    description=obj.get('description', ''),
                    type=[obj.get('type', '')],
                    id=ext_ref.get('external_id', ''),
                    wiki=ext_ref.get('url', ''),
                    reference=[ref for ref in obj.get('external_references', []) if ref.get('source_name') != 'mitre-attack'],
                    created=obj.get('created', ''),
                    modified=obj.get('modified', ''),
                    contributor=obj.get('x_mitre_contributors', []),
                    stix=obj.get('id', '')
                ))
            elif obj.get('type') == 'attack-pattern':
                ext_ref = next((ref for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), {})
                self.techniques.append(ATTCKTechnique(
                    name=obj.get('name', ''),
                    tactic=[phase.get('phase_name', '') for phase in obj.get('kill_chain_phases', [])] if obj.get('kill_chain_phases') else [],
                    description=obj.get('description', ''),
                    platform=obj.get('x_mitre_platforms', []),
                    permission=obj.get('x_mitre_permissions_required', []),
                    bypass=obj.get('x_mitre_defense_bypassed', []),
                    effective_perm=obj.get('x_mitre_effective_permissions', []),
                    network=obj.get('x_mitre_network_requirements', ''),
                    remote=obj.get('x_mitre_remote_support', ''),
                    prereq=obj.get('x_mitre_system_requirements', ''),
                    detection=obj.get('x_mitre_detection', ''),
                    mitigation="",  # Populated below
                    data_source=obj.get('x_mitre_data_sources', []),
                    id=ext_ref.get('external_id', ''),
                    wiki=ext_ref.get('url', ''),
                    reference=[ref for ref in obj.get('external_references', []) if ref.get('source_name') != 'mitre-attack'],
                    created=obj.get('created', ''),
                    modified=obj.get('modified', ''),
                    contributor=obj.get('x_mitre_contributors', []),
                    stix=obj.get('id', '')
                ))
            elif obj.get('type') == 'intrusion-set':
                ext_ref = next((ref for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), {})
                self.groups.append(ATTCKGroup(
                    name=obj.get('name', ''),
                    description=obj.get('description', ''),
                    alias=obj.get('aliases', []),
                    id=ext_ref.get('external_id', ''),
                    wiki=ext_ref.get('url', ''),
                    reference=[ref for ref in obj.get('external_references', []) if ref.get('source_name') != 'mitre-attack'],
                    created=obj.get('created', ''),
                    modified=obj.get('modified', ''),
                    contributor=obj.get('x_mitre_contributors', []),
                    stix=obj.get('id', '')
                ))
            elif obj.get('type') in ('tool', 'malware', 'software'):
                ext_ref = next((ref for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), {})
                self.software.append(ATTCKSoftware(
                    name=obj.get('name', ''),
                    description=obj.get('description', ''),
                    type=obj.get('type', ''),
                    alias=obj.get('x_mitre_aliases', []),
                    id=ext_ref.get('external_id', ''),
                    wiki=ext_ref.get('url', ''),
                    reference=[ref for ref in obj.get('external_references', []) if ref.get('source_name') != 'mitre-attack'],
                    created=obj.get('created', ''),
                    modified=obj.get('modified', ''),
                    contributor=obj.get('x_mitre_contributors', []),
                    stix=obj.get('id', '')
                ))
            elif obj.get('type') == 'relationship':
                self.relationships.append(ATTCKRelationship(
                    source=obj.get('source_ref', ''),
                    edge=obj.get('relationship_type', ''),
                    target=obj.get('target_ref', ''),
                    description=obj.get('description', ''),
                    reference=obj.get('external_references', [])
                ))

# --- Neo4j/BloodHound Integration (from PushToBH.ps1, CypherDog15_Alpha3.ps1) ---

class BloodHoundGraph:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="neo4j"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def create_node(self, label: str, properties: Dict[str, Any]):
        # Merge node to avoid duplicates
        props = {k: v for k, v in properties.items() if v not in (None, '', [], {})}
        query = f"MERGE (n:{label} {{id: $id}}) SET n += $props"
        with self.driver.session() as session:
            session.run(query, id=props['id'], props=props)

    def create_relationship(self, src_label: str, src_id: str, rel: str, tgt_label: str, tgt_id: str):
        query = (
            f"MATCH (a:{src_label} {{id: $src_id}}), (b:{tgt_label} {{id: $tgt_id}}) "
            f"MERGE (a)-[r:{rel.upper()}]->(b)"
        )
        with self.driver.session() as session:
            session.run(query, src_id=src_id, tgt_id=tgt_id)

    def run_query(self, query: str, params: dict = None):
        with self.driver.session() as session:
            return list(session.run(query, params or {}))

# --- PushToBH Logic (from PushToBH.ps1) ---

def push_attck_to_bloodhound(attck: ATTCKnowledge, bh: BloodHoundGraph):
    # Tactics as OU
    for tactic in attck.tactics:
        bh.create_node("OU", asdict(tactic))
    # Techniques as GPO
    for technique in attck.techniques:
        bh.create_node("GPO", asdict(technique))
    # Software as Computer
    for sw in attck.software:
        bh.create_node("Computer", asdict(sw))
    # Groups as Group
    for group in attck.groups:
        bh.create_node("Group", asdict(group))
    # Relationships (Technique <-> Tactic, etc.)
    for technique in attck.techniques:
        for tactic_name in technique.tactic:
            # Find tactic node by name
            tactic = next((t for t in attck.tactics if t.name == tactic_name), None)
            if tactic:
                bh.create_relationship("GPO", technique.id, "USES", "OU", tactic.id)
    for rel in attck.relationships:
        # Map STIX IDs to node labels
        src_label = stix_type_to_label(rel.source)
        tgt_label = stix_type_to_label(rel.target)
        if src_label and tgt_label:
            bh.create_relationship(src_label, rel.source, rel.edge, tgt_label, rel.target)

def stix_type_to_label(stix_id: str) -> Optional[str]:
    # Map STIX object types to BloodHound node labels
    if stix_id.startswith("intrusion-set--"):
        return "Group"
    elif stix_id.startswith("attack-pattern--"):
        return "GPO"
    elif stix_id.startswith("malware--") or stix_id.startswith("tool--"):
        return "Computer"
    elif stix_id.startswith("x-mitre-tactic--"):
        return "OU"
    return None

# --- CypherDog-like Query Functions (from CypherDog15_Alpha3.ps1) ---

def show_relationship_types(bh: BloodHoundGraph):
    query = """
    CALL db.relationshipTypes() YIELD relationshipType
    MATCH ()-[r]->()
    WHERE type(r) = relationshipType
    RETURN relationshipType, count(r) AS RelationshipCount, HEAD(keys(r)) AS SampleProperty
    """
    for record in bh.run_query(query):
        print(record)

def show_tactic_count(bh: BloodHoundGraph):
    query = """
    MATCH (n:OU)
    WHERE n.id STARTS WITH 'TA'
    RETURN count(n) AS TacticCount, n.id AS SampleID, n.name AS SampleName
    """
    for record in bh.run_query(query):
        print(record)

# --- Main Workflow (as per the Medium article) ---

def main():
    # 1. Download and parse MITRE ATT&CK data
    print("Syncing MITRE ATT&CK knowledge...")
    attck = ATTCKnowledge()
    attck.sync()
    print(f"Loaded {len(attck.tactics)} tactics, {len(attck.techniques)} techniques, {len(attck.software)} software, {len(attck.groups)} groups.")

    # 2. Connect to Neo4j/BloodHound
    print("Connecting to Neo4j...")
    bh = BloodHoundGraph(uri="bolt://localhost:7687", user="neo4j", password="neo4j")

    # 3. Push MITRE ATT&CK data to BloodHound
    print("Pushing ATT&CK data to BloodHound...")
    push_attck_to_bloodhound(attck, bh)

    # 4. Run example CypherDog queries
    print("Relationship types in BloodHound:")
    show_relationship_types(bh)
    print("Tactic node count in BloodHound:")
    show_tactic_count(bh)

    # 5. Close connection
    bh.close()

if __name__ == "__main__":
    main()
