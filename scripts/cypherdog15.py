# https://github.com/SadProcessor/SomeStuff/blob/master/CypherDog15_Alpha3.ps1
import requests
import json
import base64
import sys
import argparse
from typing import Any, Dict, List, Optional

class CypherDog:
    def __init__(self, uri: str, username: str, password: str, debug: bool = False):
        self.uri = uri.rstrip('/')
        self.username = username
        self.password = password
        self.debug = debug
        self.session = requests.Session()
        self.token = None

    def _log(self, msg: str):
        if self.debug:
            print(f"[DEBUG] {msg}")

    def authenticate(self):
        auth_url = f"{self.uri}/user/authenticate"
        payload = {
            "username": self.username,
            "password": self.password
        }
        self._log(f"Authenticating to {auth_url} as {self.username}")
        response = self.session.post(auth_url, json=payload)
        if response.status_code == 200:
            self.token = response.json()["jwt"]
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
            self._log("Authentication successful")
        else:
            raise Exception(f"Authentication failed: {response.text}")

    def run_cypher(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> Any:
        if not self.token:
            self.authenticate()
        cypher_url = f"{self.uri}/api/v1/cypher"
        payload = {"query": cypher}
        if params:
            payload["parameters"] = params
        self._log(f"Running Cypher query: {cypher}")
        response = self.session.post(cypher_url, json=payload)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Cypher query failed: {response.text}")

    def get_nodes(self, node_type: str = None) -> List[Dict[str, Any]]:
        cypher = "MATCH (n"
        if node_type:
            cypher += f":{node_type}"
        cypher += ") RETURN n"
        result = self.run_cypher(cypher)
        return [record["n"] for record in result.get("data", [])]

    def get_node(self, node_type: str, name: str) -> Optional[Dict[str, Any]]:
        cypher = f"MATCH (n:{node_type} {{name: $name}}) RETURN n"
        result = self.run_cypher(cypher, {"name": name})
        if result.get("data"):
            return result["data"][0]["n"]
        return None

    def get_edges(self, edge_type: str = None) -> List[Dict[str, Any]]:
        cypher = "MATCH ()-[r"
        if edge_type:
            cypher += f":{edge_type}"
        cypher += "]-() RETURN r"
        result = self.run_cypher(cypher)
        return [record["r"] for record in result.get("data", [])]

    def get_paths(self, start: str, end: str, rel_type: str = None, max_depth: int = 5) -> List[Dict[str, Any]]:
        rel = f":{rel_type}" if rel_type else ""
        cypher = (
            f"MATCH p=shortestPath((a)-[*..{max_depth}]{rel}-(b)) "
            f"WHERE a.name = $start AND b.name = $end "
            f"RETURN p"
        )
        result = self.run_cypher(cypher, {"start": start, "end": end})
        return [record["p"] for record in result.get("data", [])]

    def show_query(self, cypher: str):
        print(cypher)

    # Add more methods as needed to cover all CypherDog.ps1 cmdlets

def main():
    parser = argparse.ArgumentParser(description="CypherDog - Python BloodHound Dog Whisperer")
    parser.add_argument("--uri", required=True, help="Neo4j REST API base URI (e.g., http://localhost:7474)")
    parser.add_argument("--username", required=True, help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # get-nodes
    parser_nodes = subparsers.add_parser("get-nodes")
    parser_nodes.add_argument("--type", help="Node type (e.g., User, Computer)")

    # get-node
    parser_node = subparsers.add_parser("get-node")
    parser_node.add_argument("type", help="Node type")
    parser_node.add_argument("name", help="Node name")

    # get-edges
    parser_edges = subparsers.add_parser("get-edges")
    parser_edges.add_argument("--type", help="Edge type (e.g., MemberOf)")

    # get-paths
    parser_paths = subparsers.add_parser("get-paths")
    parser_paths.add_argument("start", help="Start node name")
    parser_paths.add_argument("end", help="End node name")
    parser_paths.add_argument("--rel-type", help="Relationship type")
    parser_paths.add_argument("--max-depth", type=int, default=5, help="Max path depth")

    # show-query
    parser_show = subparsers.add_parser("show-query")
    parser_show.add_argument("cypher", help="Cypher query to show")

    args = parser.parse_args()

    dog = CypherDog(args.uri, args.username, args.password, args.debug)

    if args.command == "get-nodes":
        nodes = dog.get_nodes(args.type)
        print(json.dumps(nodes, indent=2))
    elif args.command == "get-node":
        node = dog.get_node(args.type, args.name)
        print(json.dumps(node, indent=2) if node else "Node not found")
    elif args.command == "get-edges":
        edges = dog.get_edges(args.type)
        print(json.dumps(edges, indent=2))
    elif args.command == "get-paths":
        paths = dog.get_paths(args.start, args.end, args.rel_type, args.max_depth)
        print(json.dumps(paths, indent=2))
    elif args.command == "show-query":
        dog.show_query(args.cypher)

if __name__ == "__main__":
    main()
