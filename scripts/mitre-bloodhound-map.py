"""
map_bh_to_mitre_full.py
Python 3.11 script to exhaustively map BloodHound AD nodes to MITRE ATT&CK nodes.
Creates relationships between BloodHound and MITRE nodes based on analysis of AD data and MITRE ATT&CK tactics/techniques.
"""

from neo4j import GraphDatabase

# Neo4j connection settings (update as needed)
uri = "bolt://localhost:7687"
user = "neo4j"
password = "bloodhoundcommunityedition"

# Relationship types
MAPS_TO_MITRE = "MAPS_TO_MITRE"
USES_TECHNIQUE = "USES_TECHNIQUE"
USES_TACTIC = "USES_TACTIC"
ASSOCIATED_WITH = "ASSOCIATED_WITH"

class BloodhoundToMitreMapper:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def execute_cypher(self, query, **kwargs):
        """Helper to run a Cypher query and return results."""
        with self.driver.session() as session:
            return session.run(query, **kwargs)

    def map_groups_to_mitre_groups(self):
        """
        Map BloodHound groups to MITRE groups by name similarity.
        """
        query = """
        MATCH (bh:Group), (mitre:Group)
        WHERE toLower(bh.name) CONTAINS toLower(mitre.name) OR toLower(mitre.name) CONTAINS toLower(bh.name)
        MERGE (bh)-[:MAPS_TO_MITRE]->(mitre)
        RETURN bh.name AS bloodhound_group, mitre.name AS mitre_group
        """
        return self.execute_cypher(query)

    def map_privileges_to_mitre_techniques(self):
        """
        Map BloodHound privileges to MITRE techniques based on real-world mappings.
        """
        # GenericAll/Owns: Persistence (T1136), Privilege Escalation (T1068), Account Manipulation (T1098)
        query = """
        MATCH (a)-[r:GenericAll|Owns]->(b)
        MATCH (mitre:Technique)
        WHERE mitre.id IN ['T1136', 'T1068', 'T1098']
        MERGE (a)-[:USES_TECHNIQUE]->(mitre)
        RETURN a.name AS source, b.name AS target, mitre.name AS technique
        """
        self.execute_cypher(query)

        # WriteDacl: Permission Groups Discovery (T1069), Account Manipulation (T1098)
        query = """
        MATCH (a)-[r:WriteDacl]->(b)
        MATCH (mitre:Technique)
        WHERE mitre.id IN ['T1069', 'T1098']
        MERGE (a)-[:USES_TECHNIQUE]->(mitre)
        RETURN a.name AS source, b.name AS target, mitre.name AS technique
        """
        self.execute_cypher(query)

        # GenericWrite/WriteOwner: Account Manipulation (T1098)
        query = """
        MATCH (a)-[r:GenericWrite|WriteOwner]->(b)
        MATCH (mitre:Technique {id: 'T1098'})
        MERGE (a)-[:USES_TECHNIQUE]->(mitre)
        RETURN a.name AS source, b.name AS target, mitre.name AS technique
        """
        self.execute_cypher(query)

    def map_users_to_mitre_techniques(self):
        """
        Map users to MITRE techniques based on privileges, group memberships, and attack paths.
        """
        # Users with admin rights: Privilege Escalation (T1068), Credential Access (T1003), Account Manipulation (T1098)
        query = """
        MATCH (u:User)-[:MemberOf]->(g:Group {highvalue: true})
        MATCH (mitre:Technique)
        WHERE mitre.id IN ['T1068', 'T1003', 'T1098']
        MERGE (u)-[:USES_TECHNIQUE]->(mitre)
        RETURN u.name AS user, g.name AS group, mitre.name AS technique
        """
        self.execute_cypher(query)

        # Users with DCSync rights: Credential Access (T1003), Account Manipulation (T1098)
        query = """
        MATCH (u:User)-[:GenericAll|Owns]->(d:Domain)
        MATCH (mitre:Technique)
        WHERE mitre.id IN ['T1003', 'T1098']
        MERGE (u)-[:USES_TECHNIQUE]->(mitre)
        RETURN u.name AS user, d.name AS domain, mitre.name AS technique
        """
        self.execute_cypher(query)

        # Users with admin sessions: Lateral Movement (T1021)
        query = """
        MATCH (u:User)-[:HasSession]->(c:Computer)
        WHERE u.admincount = true OR c.highvalue = true
        MATCH (mitre:Technique {id: 'T1021'})
        MERGE (u)-[:USES_TECHNIQUE]->(mitre)
        RETURN u.name AS user, c.name AS computer, mitre.name AS technique
        """
        self.execute_cypher(query)

    def map_computers_to_mitre_techniques(self):
        """
        Map computers to MITRE techniques based on roles, sessions, and attack paths.
        """
        # Domain controllers: Discovery (T1018), Execution (T1059), Credential Access (T1003)
        query = """
        MATCH (c:Computer)
        WHERE c.name CONTAINS 'DC'
        MATCH (mitre:Technique)
        WHERE mitre.id IN ['T1018', 'T1059', 'T1003']
        MERGE (c)-[:USES_TECHNIQUE]->(mitre)
        RETURN c.name AS computer, mitre.name AS technique
        """
        self.execute_cypher(query)

        # Computers with admin sessions: Lateral Movement (T1021)
        query = """
        MATCH (u:User)-[:HasSession]->(c:Computer)
        WHERE u.admincount = true OR c.highvalue = true
        MATCH (mitre:Technique {id: 'T1021'})
        MERGE (c)-[:USES_TECHNIQUE]->(mitre)
        RETURN c.name AS computer, u.name AS user, mitre.name AS technique
        """
        self.execute_cypher(query)

    def map_software_to_mitre_techniques(self):
        """
        Map software to MITRE techniques.
        """
        # BloodHound: Discovery (T1018)
        query = """
        MATCH (s:Software)
        WHERE toLower(s.name) CONTAINS 'bloodhound'
        MATCH (mitre:Technique {id: 'T1018'})
        MERGE (s)-[:USES_TECHNIQUE]->(mitre)
        RETURN s.name AS software, mitre.name AS technique
        """
        self.execute_cypher(query)

        # Mimikatz: Credential Access (T1003)
        query = """
        MATCH (s:Software)
        WHERE toLower(s.name) CONTAINS 'mimikatz'
        MATCH (mitre:Technique {id: 'T1003'})
        MERGE (s)-[:USES_TECHNIQUE]->(mitre)
        RETURN s.name AS software, mitre.name AS technique
        """
        self.execute_cypher(query)

        # Process Injection (T1055), Command and Scripting Interpreter (T1059), Credentials from Password Stores (T1555)
        query = """
        MATCH (s:Software)
        WHERE toLower(s.name) CONTAINS 'powershell' OR toLower(s.name) CONTAINS 'cmd' OR toLower(s.name) CONTAINS 'psexec'
        MATCH (mitre:Technique)
        WHERE mitre.id IN ['T1055', 'T1059', 'T1555']
        MERGE (s)-[:USES_TECHNIQUE]->(mitre)
        RETURN s.name AS software, mitre.name AS technique
        """
        self.execute_cypher(query)

    def map_attack_paths_to_mitre_tactics(self):
        """
        Map attack paths to MITRE tactics.
        """
        # Paths to high-value groups: Privilege Escalation (TA0004), Lateral Movement (TA0008)
        query = """
        MATCH path=(u:User)-[*1..10]->(g:Group {highvalue: true})
        MATCH (mitre:Tactic)
        WHERE mitre.id IN ['TA0004', 'TA0008']
        MERGE (u)-[:USES_TACTIC]->(mitre)
        RETURN u.name AS user, g.name AS group, mitre.name AS tactic
        """
        self.execute_cypher(query)

        # Paths involving DCSync: Credential Access (TA0006)
        query = """
        MATCH (u:User)-[:GenericAll|Owns]->(d:Domain)
        MATCH (mitre:Tactic {id: 'TA0006'})
        MERGE (u)-[:USES_TACTIC]->(mitre)
        RETURN u.name AS user, d.name AS domain, mitre.name AS tactic
        """
        self.execute_cypher(query)

    def map_attack_paths_to_mitre_techniques(self):
        """
        Map attack paths to MITRE techniques based on path properties.
        """
        # Paths involving admin sessions: Lateral Movement (T1021)
        query = """
        MATCH path=(u:User)-[:MemberOf|HasSession*1..10]->(c:Computer)
        WHERE any(x IN nodes(path) WHERE x.highvalue = true)
        MATCH (mitre:Technique {id: 'T1021'})
        MERGE (u)-[:USES_TECHNIQUE]->(mitre)
        RETURN u.name AS user, c.name AS computer, mitre.name AS technique
        """
        self.execute_cypher(query)

        # Paths involving sensitive group membership: Privilege Escalation (T1068)
        query = """
        MATCH path=(u:User)-[:MemberOf*1..10]->(g:Group {highvalue: true})
        MATCH (mitre:Technique {id: 'T1068'})
        MERGE (u)-[:USES_TECHNIQUE]->(mitre)
        RETURN u.name AS user, g.name AS group, mitre.name AS technique
        """
        self.execute_cypher(query)

    def map_objects_to_mitre_tactics(self):
        """
        Map objects (users, groups, computers) to MITRE tactics based on context.
        """
        # Users with admin rights: Privilege Escalation (TA0004)
        query = """
        MATCH (u:User)-[:MemberOf]->(g:Group {highvalue: true})
        MATCH (mitre:Tactic {id: 'TA0004'})
        MERGE (u)-[:USES_TACTIC]->(mitre)
        RETURN u.name AS user, g.name AS group, mitre.name AS tactic
        """
        self.execute_cypher(query)

        # Computers with admin sessions: Lateral Movement (TA0008)
        query = """
        MATCH (u:User)-[:HasSession]->(c:Computer)
        WHERE u.admincount = true OR c.highvalue = true
        MATCH (mitre:Tactic {id: 'TA0008'})
        MERGE (c)-[:USES_TACTIC]->(mitre)
        RETURN c.name AS computer, u.name AS user, mitre.name AS tactic
        """
        self.execute_cypher(query)

        # Computers as domain controllers: Discovery (TA0007), Execution (TA0002)
        query = """
        MATCH (c:Computer)
        WHERE c.name CONTAINS 'DC'
        MATCH (mitre:Tactic)
        WHERE mitre.id IN ['TA0007', 'TA0002']
        MERGE (c)-[:USES_TACTIC]->(mitre)
        RETURN c.name AS computer, mitre.name AS tactic
        """
        self.execute_cypher(query)

    def map_top_mitre_techniques(self):
        """
        Map the top MITRE ATT&CK techniques based on real-world prevalence.
        Includes: Process Injection (T1055), Command and Scripting Interpreter (T1059),
        Credentials from Password Stores (T1555), Application Layer Protocol (T1071),
        Impair Defenses (T1562), Data Encrypted for Impact (T1486),
        System Information Discovery (T1082), Input Capture (T1056),
        Boot or Logon Autostart Execution (T1547), Data from Local System (T1005)[1][6].
        """
        # Map all computers to System Information Discovery (T1082) as an example
        query = """
        MATCH (c:Computer)
        MATCH (mitre:Technique {id: 'T1082'})
        MERGE (c)-[:USES_TECHNIQUE]->(mitre)
        RETURN c.name AS computer, mitre.name AS technique
        """
        self.execute_cypher(query)

        # Map all users with admin sessions to Command and Scripting Interpreter (T1059)
        query = """
        MATCH (u:User)-[:HasSession]->(c:Computer)
        WHERE u.admincount = true OR c.highvalue = true
        MATCH (mitre:Technique {id: 'T1059'})
        MERGE (u)-[:USES_TECHNIQUE]->(mitre)
        RETURN u.name AS user, c.name AS computer, mitre.name AS technique
        """
        self.execute_cypher(query)

        # Map software (e.g., PowerShell, cmd, psexec) to Command and Scripting Interpreter (T1059)
        query = """
        MATCH (s:Software)
        WHERE toLower(s.name) CONTAINS 'powershell' OR toLower(s.name) CONTAINS 'cmd' OR toLower(s.name) CONTAINS 'psexec'
        MATCH (mitre:Technique {id: 'T1059'})
        MERGE (s)-[:USES_TECHNIQUE]->(mitre)
        RETURN s.name AS software, mitre.name AS technique
        """
        self.execute_cypher(query)

        # Map software (e.g., Mimikatz) to Credentials from Password Stores (T1555)
        query = """
        MATCH (s:Software)
        WHERE toLower(s.name) CONTAINS 'mimikatz'
        MATCH (mitre:Technique {id: 'T1555'})
        MERGE (s)-[:USES_TECHNIQUE]->(mitre)
        RETURN s.name AS software, mitre.name AS technique
        """
        self.execute_cypher(query)

    def run_all_mappings(self):
        """Run all mapping methods."""
        print("Mapping BloodHound groups to MITRE groups...")
        self.map_groups_to_mitre_groups()

        print("\nMapping privileges to MITRE techniques...")
        self.map_privileges_to_mitre_techniques()

        print("\nMapping users to MITRE techniques...")
        self.map_users_to_mitre_techniques()

        print("\nMapping computers to MITRE techniques...")
        self.map_computers_to_mitre_techniques()

        print("\nMapping software to MITRE techniques...")
        self.map_software_to_mitre_techniques()

        print("\nMapping attack paths to MITRE tactics...")
        self.map_attack_paths_to_mitre_tactics()

        print("\nMapping attack paths to MITRE techniques...")
        self.map_attack_paths_to_mitre_techniques()

        print("\nMapping objects to MITRE tactics...")
        self.map_objects_to_mitre_tactics()

        print("\nMapping top MITRE techniques based on real-world prevalence...")
        self.map_top_mitre_techniques()

if __name__ == "__main__":
    mapper = BloodhoundToMitreMapper(uri, user, password)
    mapper.run_all_mappings()
    mapper.close()
