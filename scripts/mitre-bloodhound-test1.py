# ATTCKnowledge, CypherDog, and PushToBH PowerShell scripts combined and converted to Python 3.11

# ===== ATTCKnowledge.ps1 Conversion =====
# The PowerShell ATTCKnowledge script defines classes for MITRE ATT&CK objects (Tactic, Technique, Group, Software)
# and a function (Invoke-ATTCKnowledge) to fetch and format the ATT&CK data. We replicate those classes and functionality below.

class ATTCKTactic:
    """Represents a MITRE ATT&CK Tactic."""
    def __init__(self, name, description, type_list, ID, wiki, reference, created, modified):
        # In PowerShell, this corresponds to class ATTCKTactic with properties Name, Description, Type, ID, Wiki, Reference, Created, Modified.
        self.Name = name
        self.Description = description
        self.Type = type_list            # List of ATT&CK matrices (domains) this tactic belongs to (e.g., ["Enterprise"], ["PRE-ATT&CK"]).
        self.ID = ID                    # External ID (e.g., TA0001 for tactics) or internal if external not available.
        self.Wiki = wiki                # URL to MITRE ATT&CK wiki page.
        self.Reference = reference      # Reference object (e.g., external reference info from MITRE data).
        self.Created = created          # Timestamp of creation (from MITRE data).
        self.Modified = modified        # Timestamp of last modification.

class ATTCKTechnique:
    """Represents a MITRE ATT&CK Technique."""
    def __init__(self, name, description, tactics, platforms, ID, wiki, reference, created, modified):
        # PowerShell class ATTCKTechnique properties mapped accordingly.
        self.Name = name
        self.Description = description
        self.Tactics = tactics          # List of tactic (phase) names or IDs this technique is associated with.
        self.Platforms = platforms      # List of platforms for which this technique is applicable (from x_mitre_platforms field).
        self.ID = ID                    # External ID (e.g., T1003) or fallback to internal ID if external not available.
        self.Wiki = wiki                # URL to MITRE ATT&CK technique page.
        self.Reference = reference      # MITRE external reference object containing ID/URL.
        self.Created = created
        self.Modified = modified

class ATTCKGroup:
    """Represents a MITRE ATT&CK Threat Actor Group (Intrusion Set)."""
    def __init__(self, name, description, aliases, ID, wiki, reference, created, modified):
        # PowerShell class ATTCKGroup properties.
        self.Name = name
        self.Description = description
        self.Aliases = aliases          # List of known aliases for the group (from "aliases" field in MITRE data).
        self.ID = ID                    # External ID (e.g., G0045) or internal if external not available.
        self.Wiki = wiki                # URL to MITRE ATT&CK group page.
        self.Reference = reference      # External reference object for the group (contains ID/URL).
        self.Created = created
        self.Modified = modified

class ATTCKSoftware:
    """Represents a MITRE ATT&CK Software (Tool or Malware)."""
    def __init__(self, name, description, aliases, software_type, ID, wiki, reference, created, modified):
        # PowerShell class ATTCKSoftware properties.
        self.Name = name
        self.Description = description
        self.Aliases = aliases          # List of aliases or synonyms for the software.
        self.Type = software_type       # Type of software: "Tool" or "Malware".
        self.ID = ID                    # External ID (if available) or internal ID.
        self.Wiki = wiki                # URL to MITRE ATT&CK software page.
        self.Reference = reference      # External reference object.
        self.Created = created
        self.Modified = modified

class ATTCKRelationship:
    """Represents a relationship between ATT&CK objects (e.g., Group uses Technique)."""
    def __init__(self, sourceID, targetID, relationship_type):
        # This class is not explicitly defined in PowerShell but we create it to handle relationships similarly.
        self.SourceID = sourceID        # STIX ID of source object (could be a group, software, etc.).
        self.TargetID = targetID        # STIX ID of target object (e.g., technique or software).
        self.Type = relationship_type   # Relationship type (e.g., "uses").

def fetch_attck_data(verbose=False):
    """
    Equivalent to Invoke-ATTCKnowledge -Sync.
    Fetches MITRE ATT&CK datasets (Enterprise, PRE-ATT&CK, Mobile) from MITRE's public GitHub repository,
    then formats the data into ATTCKTactic, ATTCKTechnique, ATTCKGroup, ATTCKSoftware objects.
    Returns a dictionary containing lists of all objects and relationships.
    """
    # MITRE provides the ATT&CK content in JSON (STIX) format on GitHub (similar to how the PS script fetched data from GitHub).
    # URLs for the ATT&CK STIX JSON files:
    enterprise_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    preattack_url = "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json"
    mobile_url   = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
    data_sources = [("Enterprise", enterprise_url), ("PRE-ATT&CK", preattack_url), ("Mobile", mobile_url)]

    # Containers for parsed objects:
    tactics_list = []
    techniques_list = []
    groups_list = []
    software_list = []
    relationships_list = []

    for domain_name, url in data_sources:
        try:
            # Use requests to fetch the JSON data (similar to Invoke-RestMethod in PowerShell).
            response = requests.get(url)
            response.raise_for_status()
        except Exception as e:
            if verbose:
                print(f"[!] Error fetching {domain_name} ATT&CK data: {e}")
            continue
        try:
            attack_data = response.json()
        except Exception as e:
            if verbose:
                print(f"[!] Error parsing JSON for {domain_name}: {e}")
            continue

        if verbose:
            print(f"[+] Importing {domain_name} ATT&CK data...")

        # Build index to map STIX object IDs to our objects (for relationships linking)
        stix_object_index = {}

        # Iterate through all objects in the STIX JSON:
        for obj in attack_data.get("objects", []):
            obj_type = obj.get("type")
            # Handle Tactic objects (type: x-mitre-tactic)
            if obj_type == "x-mitre-tactic":
                name = obj.get("name", "")
                description = obj.get("description", "")
                # Each tactic belongs to a particular ATT&CK matrix domain.
                type_list = [domain_name]  # e.g. "Enterprise", "PRE-ATT&CK", or "Mobile"
                # Find external reference for MITRE ATT&CK that provides the tactic ID and wiki URL.
                ext_refs = obj.get("external_references", [])
                mitre_id = None
                mitre_url = None
                reference_obj = None
                for ref in ext_refs:
                    # source_name might be "mitre-attack", "mitre-pre-attack", or "mitre-mobile-attack"
                    if ref.get("source_name", "").startswith("mitre"):
                        mitre_id = ref.get("external_id")
                        mitre_url = ref.get("url")
                        reference_obj = ref
                        break
                # If not found, fall back to the first reference if available.
                if reference_obj is None and ext_refs:
                    reference_obj = ext_refs[0]
                    mitre_id = mitre_id or reference_obj.get("external_id")
                    mitre_url = mitre_url or reference_obj.get("url")
                # Use external_id as tactic ID (e.g., TA0001) or fallback to STIX id.
                tactic_id = mitre_id if mitre_id else obj.get("id")
                created = obj.get("created")
                modified = obj.get("modified")
                # Instantiate ATTCKTactic object
                tactic_obj = ATTCKTactic(name, description, type_list, tactic_id, mitre_url, reference_obj, created, modified)
                tactics_list.append(tactic_obj)
                stix_object_index[obj["id"]] = tactic_obj

            # Handle Technique objects (type: attack-pattern)
            elif obj_type == "attack-pattern":
                name = obj.get("name", "")
                description = obj.get("description", "")
                # kill_chain_phases contains tactic info (phase_name is the tactical category)
                tactic_phases = []
                for phase in obj.get("kill_chain_phases", []):
                    # Include phases from the relevant kill_chain (mitre attack or mobile or pre-attack)
                    if phase.get("kill_chain_name", "").startswith("mitre"):
                        tactic_phases.append(phase.get("phase_name"))
                # Platforms on which this technique is applicable
                platforms = obj.get("x_mitre_platforms", []) or []
                # External reference for technique ID and URL (source_name "mitre-attack" etc.)
                ext_refs = obj.get("external_references", [])
                mitre_id = None
                mitre_url = None
                reference_obj = None
                for ref in ext_refs:
                    if ref.get("source_name", "").startswith("mitre"):
                        mitre_id = ref.get("external_id")
                        mitre_url = ref.get("url")
                        reference_obj = ref
                        break
                if reference_obj is None and ext_refs:
                    reference_obj = ext_refs[0]
                    mitre_id = mitre_id or reference_obj.get("external_id")
                    mitre_url = mitre_url or reference_obj.get("url")
                technique_id = mitre_id if mitre_id else obj.get("id")
                created = obj.get("created")
                modified = obj.get("modified")
                # Instantiate ATTCKTechnique
                technique_obj = ATTCKTechnique(name, description, tactic_phases, platforms, technique_id, mitre_url, reference_obj, created, modified)
                techniques_list.append(technique_obj)
                stix_object_index[obj["id"]] = technique_obj

            # Handle Group objects (type: intrusion-set, representing threat actor groups)
            elif obj_type == "intrusion-set":
                name = obj.get("name", "")
                description = obj.get("description", "")
                aliases = obj.get("aliases", []) or []  # list of group aliases
                ext_refs = obj.get("external_references", [])
                mitre_id = None
                mitre_url = None
                reference_obj = None
                for ref in ext_refs:
                    if ref.get("source_name", "").startswith("mitre"):
                        mitre_id = ref.get("external_id")
                        mitre_url = ref.get("url")
                        reference_obj = ref
                        break
                if reference_obj is None and ext_refs:
                    reference_obj = ext_refs[0]
                    mitre_id = mitre_id or reference_obj.get("external_id")
                    mitre_url = mitre_url or reference_obj.get("url")
                group_id = mitre_id if mitre_id else obj.get("id")
                created = obj.get("created")
                modified = obj.get("modified")
                # Instantiate ATTCKGroup
                group_obj = ATTCKGroup(name, description, aliases, group_id, mitre_url, reference_obj, created, modified)
                groups_list.append(group_obj)
                stix_object_index[obj["id"]] = group_obj

            # Handle Software objects (types: tool, malware)
            elif obj_type in ("tool", "malware"):
                name = obj.get("name", "")
                description = obj.get("description", "")
                # Tools and malware might have an "x_mitre_aliases" field or "aliases"
                aliases = obj.get("x_mitre_aliases", []) or obj.get("aliases", []) or []
                software_type = "Tool" if obj_type == "tool" else "Malware"
                ext_refs = obj.get("external_references", [])
                mitre_id = None
                mitre_url = None
                reference_obj = None
                for ref in ext_refs:
                    if ref.get("source_name", "").startswith("mitre"):
                        mitre_id = ref.get("external_id")
                        mitre_url = ref.get("url")
                        reference_obj = ref
                        break
                if reference_obj is None and ext_refs:
                    reference_obj = ext_refs[0]
                    mitre_id = mitre_id or reference_obj.get("external_id")
                    mitre_url = mitre_url or reference_obj.get("url")
                software_id = mitre_id if mitre_id else obj.get("id")
                created = obj.get("created")
                modified = obj.get("modified")
                # Instantiate ATTCKSoftware
                software_obj = ATTCKSoftware(name, description, aliases, software_type, software_id, mitre_url, reference_obj, created, modified)
                software_list.append(software_obj)
                stix_object_index[obj["id"]] = software_obj

            # Handle Relationship objects (type: relationship, e.g., usage relationships between objects)
            elif obj_type == "relationship":
                rel_type = obj.get("relationship_type")
                source_ref = obj.get("source_ref")   # STIX ID of source object
                target_ref = obj.get("target_ref")   # STIX ID of target object
                # We're interested in "uses" relationships (Group uses Software or Technique, Software uses Technique, etc.)
                if rel_type == "uses":
                    relationship_obj = ATTCKRelationship(source_ref, target_ref, rel_type)
                    relationships_list.append(relationship_obj)
                    # (We will resolve these to actual nodes when pushing to Neo4j)

        if verbose:
            print(f"[+] Processed {domain_name} ATT&CK objects.")

    if verbose:
        print("[+] ATT&CK data import and formatting complete.")
    # Return a dictionary of all collected objects.
    return {
        "Tactics": tactics_list,
        "Techniques": techniques_list,
        "Groups": groups_list,
        "Software": software_list,
        "Relationships": relationships_list
    }

# ===== CypherDog15_Alpha3.ps1 Conversion =====
# The CypherDog script provides functionality to interact with the Neo4j (BloodHound) database via its REST API.
# We'll set up the connection parameters and helper functions to send queries, similar to what CypherDog does.
import requests
import json

# Connection configuration (Neo4j server running BloodHound DB).
Server = "localhost"
Port = "7474"
# Build the REST API endpoint URL for Cypher queries (Neo4j 3.x uses /db/data/cypher for queries).
Neo4j_Cypher_URL = f"http://{Server}:{Port}/db/neo4j/tx/commit"
# HTTP headers for JSON format
Headers = {
    'Accept': 'application/json; charset=UTF-8',
    'Content-Type': 'application/json'
}

def send_cypher_query(query, params=None):
    """
    Sends a Cypher query to the Neo4j REST API and returns the JSON result.
    Equivalent to using Invoke-RestMethod in PowerShell with the constructed body.
    """
    body = {
        "query": query,
        "params": params or {}
    }
    try:
        response = requests.post(Neo4j_Cypher_URL, headers=Headers, data=json.dumps(body))
        response.raise_for_status()  # Raise exception for HTTP errors (e.g., if Neo4j is not reachable)
    except requests.RequestException as e:
        # If there's an error, we print it (similar to PowerShell script which showed errors but continued).
        print(f"[!] Error executing Cypher query: {e}")
        return None
    try:
        return response.json()
    except ValueError:
        return None

def add_node(label, properties):
    """
    Create or merge a node with the given label and properties in the Neo4j database.
    This function constructs a Cypher MERGE query.
    """
    # Construct MERGE query with parameterized properties.
    # We use ID as the unique property for merging (ensuring no duplicates for the same object).
    prop_assignments = ", ".join([f"n.{key} = {{P_{key}}}" for key in properties.keys()])
    query = f"MERGE (n:{label} {{ID: {{P_ID}}}}) SET {prop_assignments}"
    # Prepare parameters dictionary with prefix P_ for each property
    params = {f"P_{key}": value for key, value in properties.items()}
    # Ensure there's an ID param (if the object uses 'ID' property as unique key).
    params["P_ID"] = properties.get("ID") or properties.get("name") or properties.get("Name")
    # Execute the query via REST API
    return send_cypher_query(query, params)

def add_relationship(source_label, source_id, rel_type, target_label, target_id):
    """
    Create a relationship of type rel_type between two nodes identified by their labels and unique IDs.
    This function will MATCH the source and target nodes by ID and MERGE the relationship.
    """
    query = (f"MATCH (a:{source_label} {{ID: {{P_source}}}}), "
             f"(b:{target_label} {{ID: {{P_target}}}}) "
             f"MERGE (a)-[r:{rel_type}]->(b)")
    params = {"P_source": source_id, "P_target": target_id}
    return send_cypher_query(query, params)

# (CypherDog also likely provided various query helper functions for BloodHound data retrieval,
# but for this conversion task we focus on the insertion functionality as needed by PushToBH.)

# ===== PushToBH.ps1 Conversion =====
# The PushToBH script orchestrates the process:
# It uses ATTCKnowledge to get the data, then uses CypherDog functions to push nodes and relationships into Neo4j.
# We combine these steps in the push_to_bloodhound function. We also include any ASCII art or user output from the original scripts.

def push_to_bloodhound():
    """Main routine to load ATT&CK data and push it into BloodHound's Neo4j database."""
    # Print ASCII art banners (from CypherDog and ATTCKnowledge scripts)
    # CypherDog v1.5 Alpha3 ASCII banner (as seen in the PowerShell script output).
    print("--------------------------------------------")
    print("           ______  CYPHERDOG1.5            ")
    print("                 ______  Alpha3            ")
    print("   BloodHound Dog Whisperer - @SadProcessor 2018")
    print("   - v1.5 aka The 'Good Boy' Edition -")
    print("--------------------------------------------")
    # ATTCKnowledge ASCII art banner.
    print("========================================")
    print("            ATTCKnowledge              ")
    print("   #                        #         ")
    print("   {0,0}                                ")
    print("   /)  )                                ")
    print("   /--\\    @                           ")
    print("   ATT&CK                               ")
    print("========================================")
    print("   __ SadProcessor 2019 __             ")
    print("========================================")

    # Invoke the ATTCK data fetch (equivalent to ATTCKnowledge -Sync -Verbose).
    attck_data = fetch_attck_data(verbose=True)

    # Define mapping of ATT&CK object types to BloodHound node labels.
    # These mappings were chosen to align with BloodHound's expected node types so that icons display distinctively.
    TechniqueLabel = "GPO"      # Use "GPO" (Group Policy Object) label to represent a Technique node
    GroupLabel = "Group"        # Use "Group" label for Threat Actor Group (BloodHound's group icon)
    SoftwareLabel = "Computer"  # Use "Computer" label for Software (tools/malware) to reuse the computer icon
    TacticLabel = "OU"          # Use "OU" (Organizational Unit) label for Tactics (as a category folder icon)

    # Insert all Technique nodes into Neo4j
    for tech in attck_data["Techniques"]:
        node_properties = {
            "ID": tech.ID,
            "name": tech.Name,
            "description": tech.Description
        }
        add_node(TechniqueLabel, node_properties)

    # Insert all Group nodes
    for grp in attck_data["Groups"]:
        node_properties = {
            "ID": grp.ID,
            "name": grp.Name,
            "description": grp.Description
        }
        add_node(GroupLabel, node_properties)

    # Insert all Software nodes (tools and malware)
    for sw in attck_data["Software"]:
        node_properties = {
            "ID": sw.ID,
            "name": sw.Name,
            "description": sw.Description
        }
        add_node(SoftwareLabel, node_properties)

    # Insert all Tactic nodes
    for tac in attck_data["Tactics"]:
        node_properties = {
            "ID": tac.ID,
            "name": tac.Name,
            "description": tac.Description
        }
        add_node(TacticLabel, node_properties)

    # Insert all relationships (uses relationships between groups, software, and techniques).
    for rel in attck_data["Relationships"]:
        src_id = rel.SourceID   # STIX ID of the source object
        tgt_id = rel.TargetID   # STIX ID of the target object
        rel_type = "Uses"       # We'll label all these relationships as "Uses"

        # Determine source and target labels by looking at STIX ID prefixes (intrusion-set--, malware--, tool--, attack-pattern--, x-mitre-tactic--).
        source_label = None
        target_label = None
        if src_id.startswith("intrusion-set--"):
            source_label = GroupLabel
        elif src_id.startswith("attack-pattern--"):
            source_label = TechniqueLabel
        elif src_id.startswith("malware--") or src_id.startswith("tool--"):
            source_label = SoftwareLabel
        elif src_id.startswith("x-mitre-tactic--"):
            source_label = TacticLabel

        if tgt_id.startswith("intrusion-set--"):
            target_label = GroupLabel
        elif tgt_id.startswith("attack-pattern--"):
            target_label = TechniqueLabel
        elif tgt_id.startswith("malware--") or tgt_id.startswith("tool--"):
            target_label = SoftwareLabel
        elif tgt_id.startswith("x-mitre-tactic--"):
            target_label = TacticLabel

        if source_label is None or target_label is None:
            # If we can't determine the type (should not happen for "uses" relationships in ATT&CK data), skip.
            continue

        # Determine the external IDs we used as node IDs in the database:
        # The objects in attck_data have external IDs as their .ID attribute (if available).
        # If an object didn't have an external_id, .ID might be the full STIX ID. We must match those.
        source_ext_id = None
        target_ext_id = None

        # Find source external ID by checking the lists of objects
        if source_label == TechniqueLabel:
            for tech in attck_data["Techniques"]:
                # If the STIX IDs match (or the external reference object matches by ID), use the object's ID field.
                # (tech.ID is already the external technique ID if available, otherwise STIX ID).
                if src_id == tech.Reference.get("source_id", "") or src_id == tech.Reference.get("source_ref", "") or src_id == tech.ID:
                    source_ext_id = tech.ID
                    break
        elif source_label == GroupLabel:
            for grp in attck_data["Groups"]:
                if src_id == grp.Reference.get("source_id", "") or src_id == grp.Reference.get("source_ref", "") or src_id == grp.ID:
                    source_ext_id = grp.ID
                    break
        elif source_label == SoftwareLabel:
            for sw in attck_data["Software"]:
                if src_id == sw.Reference.get("source_id", "") or src_id == sw.Reference.get("source_ref", "") or src_id == sw.ID:
                    source_ext_id = sw.ID
                    break
        elif source_label == TacticLabel:
            for tac in attck_data["Tactics"]:
                if src_id == tac.Reference.get("source_id", "") or src_id == tac.Reference.get("source_ref", "") or src_id == tac.ID:
                    source_ext_id = tac.ID
                    break

        # Find target external ID similarly
        if target_label == TechniqueLabel:
            for tech in attck_data["Techniques"]:
                if tgt_id == tech.Reference.get("source_id", "") or tgt_id == tech.Reference.get("source_ref", "") or tgt_id == tech.ID:
                    target_ext_id = tech.ID
                    break
        elif target_label == GroupLabel:
            for grp in attck_data["Groups"]:
                if tgt_id == grp.Reference.get("source_id", "") or tgt_id == grp.Reference.get("source_ref", "") or tgt_id == grp.ID:
                    target_ext_id = grp.ID
                    break
        elif target_label == SoftwareLabel:
            for sw in attck_data["Software"]:
                if tgt_id == sw.Reference.get("source_id", "") or tgt_id == sw.Reference.get("source_ref", "") or tgt_id == sw.ID:
                    target_ext_id = sw.ID
                    break
        elif target_label == TacticLabel:
            for tac in attck_data["Tactics"]:
                if tgt_id == tac.Reference.get("source_id", "") or tgt_id == tac.Reference.get("source_ref", "") or tgt_id == tac.ID:
                    target_ext_id = tac.ID
                    break

        # If not found via references, default to using the STIX IDs directly (which would match if we inserted nodes with STIX IDs in .ID).
        if source_ext_id is None:
            source_ext_id = src_id
        if target_ext_id is None:
            target_ext_id = tgt_id

        # Add the relationship to the database
        add_relationship(source_label, source_ext_id, rel_type, target_label, target_ext_id)

    # if verbose:
        print("[+] Completed pushing ATT&CK data to BloodHound (Neo4j). You can now query it via the BloodHound interface.")

# Run the push routine. In PowerShell, this would be done by executing ./PushToBH.ps1
if __name__ == "__main__":
    push_to_bloodhound()
