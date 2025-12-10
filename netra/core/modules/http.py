import aiohttp
import ssl
from typing import Dict, Any
from vortex.core.scanner import BaseScanner
from vortex.core.http import SafeHTTPClient

class HTTPScanner(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        # Ensure target has protocol
        if not target.startswith("http"):
            target = f"http://{target}"
            
        results = {}
        
        try:
            async with SafeHTTPClient() as client:
                response = await client.get(target, ssl=False, timeout=5)
                results["status_code"] = response.status
                results["headers"] = dict(response.headers)
                results["server"] = response.headers.get("Server", "Unknown")
                
                # Basic tech stack fingerprinting based on headers
                tech_stack = []
                if "X-Powered-By" in response.headers:
                    tech_stack.append(response.headers["X-Powered-By"])
                results["tech_stack"] = tech_stack
                    
        except Exception as e:
            results["error"] = str(e)
            
        return results
