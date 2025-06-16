from neo4j import GraphDatabase
from typing import Dict, List
import asyncio
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ATTCKTechnique:
    tid: str
    name: str
    tactic: str
    description: str


@dataclass
class ADObject:
    name: str
    type: str
    properties: Dict


class ATTCKBloodhound:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
        self.session = None

    async def __aenter__(self):
        self.session = self.driver.session(database="neo4j")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
        self.driver.close()

    async def create_technique(self, technique: ATTCKTechnique):
        query = """
            MERGE (t:Technique {
                TID: $tid,
                name: $name,
                tactic: $tactic,
                description: $description,
                lastUpdated: $timestamp
            })
            RETURN t
        """
        params = {
            "tid": technique.tid,
            "name": technique.name,
            "tactic": technique.tactic,
            "description": technique.description,
            "timestamp": datetime.now().isoformat()
        }
        result = await self.session.execute_write(
            lambda tx: tx.run(query, params)
        )
        return result.single()

    async def create_ad_object(self, obj: ADObject):
        query = """
            MERGE (o:{type} {
                name: $name,
                properties: $properties
            })
            RETURN o
        """.format(type=obj.type)
        result = await self.session.execute_write(
            lambda tx: tx.run(query, {
                "name": obj.name,
                "properties": obj.properties
            })
        )
        return result.single()

    async def link_technique_to_object(self, technique_tid: str, object_name: str, object_type: str):
        query = """
            MATCH (t:Technique{TID: $technique_tid})
            MATCH (o:{type}{name: $object_name})
            MERGE (o)-[:USES_TECHNIQUE]->(t)
            RETURN t, o
        """.format(type=object_type)
        result = await self.session.execute_write(
            lambda tx: tx.run(query, {
                "technique_tid": technique_tid,
                "object_name": object_name
            })
        )
        return result.single()

    async def find_techniques_by_tactic(self, tactic: str):
        query = """
            MATCH (t:Technique {tactic: $tactic})
            RETURN t.TID as tid, t.name as name
            ORDER BY t.name
        """
        result = await self.session.execute_read(
            lambda tx: tx.run(query, {"tactic": tactic})
        )
        return [record for record in result]

    async def find_objects_using_technique(self, technique_tid: str):
        query = """
            MATCH (o)-[:USES_TECHNIQUE]->(t:Technique{TID: $technique_tid})
            RETURN DISTINCT o.name as name, TYPE(o) as type
        """
        result = await self.session.execute_read(
            lambda tx: tx.run(query, {"technique_tid": technique_tid})
        )
        return [record for record in result]


# Example usage
async def main():
    async with ATTCKBloodhound(
            neo4j_uri="bolt://localhost:7687",
            neo4j_user="neo4j",
            neo4j_password="password"
    ) as attck:

        # Create a technique
        technique = ATTCKTechnique(
            tid="T1087",
            name="Account Discovery",
            tactic="Discovery",
            description="Discovery of local or domain accounts"
        )
        await attck.create_technique(technique)

        # Create an AD object
        computer = ADObject(
            name="DC01",
            type="Computer",
            properties={
                "operatingSystem": "Windows Server 2022",
                "lastLogon": "2025-06-04"
            }
        )
        await attck.create_ad_object(computer)

        # Link technique to object
        await attck.link_technique_to_object("T1087", "DC01", "Computer")

        # Query techniques by tactic
        discovery_techniques = await attck.find_techniques_by_tactic("Discovery")
        print("Discovery Techniques:")
        for t in discovery_techniques:
            print(f"- {t['name']} ({t['tid']})")

        # Find objects using a technique
        objects = await attck.find_objects_using_technique("T1087")
        print("\nObjects using T1087:")
        for o in objects:
            print(f"- {o['name']} ({o['type']})")


if __name__ == "__main__":
    asyncio.run(main())