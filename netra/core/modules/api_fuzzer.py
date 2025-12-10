import logging
import json
import asyncio
from typing import Dict, Any, List
from vortex.core.scanner import BaseScanner
from vortex.core.http import SafeHTTPClient

logger = logging.getLogger("vortex.core.api")

class APIScanner(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        API Security: Detects OpenAPI/Swagger definitions and fuzzes endpoints.
        """
        results = {
            "swagger_detected": False,
            "endpoints_fuzzed": 0,
            "vulnerabilities": []
        }
        
        target = target if target.startswith("http") else f"http://{target}"
        base_url = target.rstrip("/")
        
        # 1. Discovery: Check common Swagger locations
        swagger_paths = [
            "/swagger.json",
            "/openapi.json",
            "/api/docs",
            "/v2/api-docs",
            "/api/swagger.json"
        ]
        
        found_schema = None
        
        async with SafeHTTPClient() as client:
            for path in swagger_paths:
                try:
                    url = f"{base_url}{path}"
                    resp = await client.get(url, timeout=5)
                    if resp.status == 200:
                        try:
                            # Try parsing as JSON
                            schema = await resp.json()
                            if "swagger" in schema or "openapi" in schema:
                                found_schema = schema
                                results["swagger_detected"] = True
                                results["schema_url"] = url
                                logger.info(f"Found Swagger schema at {url}")
                                break
                        except:
                            pass
                except Exception:
                    continue
            
            # 2. Fuzzing (if schema found)
            if found_schema:
                await self._fuzz_schema(found_schema, base_url, client, results)
            
            # 3. Shadow API Detection (Zombie APIs)
            # Scan JS files for endpoints NOT in the schema
            await self._find_shadow_apis(base_url, client, results, found_schema)
                
        return results

    async def _find_shadow_apis(self, base_url: str, client: SafeHTTPClient, results: Dict, schema: Dict = None):
        import re
        known_paths = set()
        if schema:
            known_paths = set(schema.get("paths", {}).keys())
            
        logger.info(f"Scanning for Shadow APIs on {base_url}")
        try:
            # Fetch Index
            resp = await client.get(base_url, timeout=10)
            if resp.status != 200: return
            html = await resp.text()
            
            # Extract JS links
            js_links = re.findall(r'src=["\'](.*?\.js)["\']', html)
            
            for link in js_links[:5]: # Limit 5
                if not link.startswith("http"):
                     link = f"{base_url.rstrip('/')}/{link.lstrip('/')}"
                
                try:
                    js_resp = await client.get(link, timeout=5)
                    if js_resp.status == 200:
                        js_code = await js_resp.text()
                        # Regex for API-like paths
                        # Matches /api/v1/users, /v2/admin/delete, etc.
                        api_matches = re.findall(r'["\'](/api/v[0-9]/[a-zA-Z0-9_/-]+)["\']', js_code)
                        api_matches += re.findall(r'["\'](/v[0-9]/[a-zA-Z0-9_/-]+)["\']', js_code)
                        
                        for api_path in api_matches:
                            # Normalize
                            if api_path not in known_paths:
                                results["vulnerabilities"].append({
                                    "type": "Shadow API (Zombie Endpoint)",
                                    "severity": "High",
                                    "endpoint": f"{link} -> {api_path}",
                                    "details": f"Found API endpoint '{api_path}' in JS source that is not documented in Swagger.",
                                    "evidence": api_path
                                })
                except Exception:
                    pass
        except Exception:
            pass

    async def _fuzz_schema(self, schema: Dict, base_url: str, client: SafeHTTPClient, results: Dict):
        paths = schema.get("paths", {})
        
        fuzz_tasks = []
        
        for path, methods in paths.items():
            for method_name, details in methods.items():
                if method_name.upper() not in ["GET", "POST", "PUT", "DELETE"]:
                    continue
                
                # Construct Fuzz URL
                # Replace {id} with test IDs for BOLA check
                fuzzed_path = path.replace("{id}", "1").replace("{userId}", "1")
                # Also try a high number to check for error handling
                err_path = path.replace("{id}", "999999").replace("{userId}", "999999")
                
                url = f"{base_url}{fuzzed_path}"
                
                # Check 1: ID Enumeration / Access Check
                fuzz_tasks.append(self._check_endpoint(client, method_name, url, "BOLA/ID Check", results))
                
                # Check 2: Error Handling / Info Leak
                if err_path != fuzzed_path:
                     err_url = f"{base_url}{err_path}"
                     fuzz_tasks.append(self._check_endpoint(client, method_name, err_url, "Error Handling", results))

                results["endpoints_fuzzed"] += 1
                if results["endpoints_fuzzed"] > 20: # Cap at 20 endpoints to avoid excessive traffic
                     break
            if results["endpoints_fuzzed"] > 20:
                break
                
        await asyncio.gather(*fuzz_tasks)

    async def _check_endpoint(self, client, method, url, check_type, results):
        try:
            resp = await client.request(method, url, timeout=5)
            
            # Simple Heuristics
            if resp.status == 500:
                 results["vulnerabilities"].append({
                     "type": "API Server Error (Potential DoS)",
                     "severity": "Medium",
                     "endpoint": f"{method} {url}",
                     "details": "Server returned 500 Internal Server Error. Input validation might be missing."
                 })
            elif resp.status == 200 and "BOLA" in check_type:
                 # If we accessed ID 1 without auth, it's interesting (oversimplified BOLA check)
                 # Real BOLA requires auth context, but this proves the endpoint is reachable.
                 results["vulnerabilities"].append({
                     "type": "Unauthenticated API Access",
                     "severity": "Low", 
                     "endpoint": f"{method} {url}",
                     "details": "Endpoint is publicly accessible. Verify if this data should be public."
                 })
                 
        except Exception as e:
            pass
