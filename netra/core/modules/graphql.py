import aiohttp
import logging
import json
from typing import Dict, Any, List
from vortex.core.scanner import BaseScanner
from vortex.core.http import SafeHTTPClient

logger = logging.getLogger("vortex.core.graphql")

class GraphQLScanner(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Scans for exposed GraphQL endpoints and introspection vulnerabilities.
        """
        results = {
            "endpoints": [],
            "introspection_enabled": False,
            "vulnerabilities": []
        }
        
        # Normalize target
        if not target.startswith("http"):
            target = f"https://{target}"
            
        common_endpoints = [
            "/graphql",
            "/api/graphql",
            "/v1/graphql",
            "/graph"
        ]
        
        async with SafeHTTPClient() as client:
            for endpoint in common_endpoints:
                url = f"{target.rstrip('/')}{endpoint}"
                try:
                    # 1. Check if endpoint exists
                    # Some servers require POST, some allow GET. We force POST with empty query to see parsing error or valid response.
                    payload = {"query": "{__typename}"}
                    response = await client.post(url, json=payload, timeout=5)
                    
                    if response.status == 200 and "data" in await response.text():
                        results["endpoints"].append(url)
                        logger.info(f"GraphQL endpoint found: {url}")
                        
                        # 2. Check Introspection
                        introspection_query = {
                            "query": """
                            query {
                              __schema {
                                types {
                                  name
                                }
                              }
                            }
                            """
                        }
                        params_resp = await client.post(url, json=introspection_query, timeout=5)
                        if params_resp.status == 200:
                            resp_json = await params_resp.json()
                            if "data" in resp_json and "__schema" in resp_json["data"]:
                                results["introspection_enabled"] = True
                                results["vulnerabilities"].append({
                                    "type": "GraphQL Introspection",
                                    "severity": "Medium",
                                    "details": f"Introspection Query enabled on {url}. Attackers can map the entire schema.",
                                    "evidence": "Schema returned successfully"
                                })
                                
                                # 3. Check for Depth/Complexity (Simulation)
                                results["vulnerabilities"].append({
                                    "type": "Potential DoS (Query Depth)",
                                    "severity": "Low",
                                    "details": "Public introspection suggests strict query depth limits might be missing.",
                                    "evidence": "N/A (Heuristic)"
                                })
                                        
                except Exception as e:
                    logger.debug(f"Failed to check GraphQL {url}: {e}")
                    
        return results
