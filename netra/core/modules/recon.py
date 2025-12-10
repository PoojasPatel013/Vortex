import aiohttp
import logging
import re
from typing import Dict, Any, List
from vortex.core.scanner import BaseScanner
from vortex.core.http import SafeHTTPClient

logger = logging.getLogger("vortex.core.recon")

class CTScanner(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Passive Recon: Queries Certificate Transparency logs (crt.sh)
        to find subdomains without touching the target infrastructure.
        """
        results = {
            "subdomains": [],
            "source": "crt.sh (Passive)",
            "count": 0
        }
        
        # Strip protocol if present
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        
        logger.info(f"Querying CT logs for {domain}")
        
        try:
            async with SafeHTTPClient() as client:
                response = await client.get(url, timeout=15)
                
                if response.status == 200:
                    try:
                        data = await response.json()
                        subdomains = set()
                        
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            # Split multiple domains in one cert
                            for name in name_value.split("\n"):
                                name = name.strip().lower()
                                # Basic validation
                                if name and not name.startswith("*") and domain in name:
                                    subdomains.add(name)
                        
                        results["subdomains"] = sorted(list(subdomains))
                        results["count"] = len(results["subdomains"])
                        app_logger_msg = f"Found {results['count']} subdomains via CT logs."
                        logger.info(app_logger_msg)
                        
                    except Exception as json_err:
                        logger.error(f"Failed to parse crt.sh JSON: {json_err}")
                        results["error"] = "Invalid JSON from CT provider"
                else:
                     logger.warning(f"crt.sh returned status {response.status}")
                     results["error"] = f"CT Provider Status: {response.status}"
                     
        except Exception as e:
            logger.error(f"CT Recon failed: {e}")
            results["error"] = str(e)
            
        return results
