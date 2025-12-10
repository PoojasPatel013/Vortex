import re
import math
import logging
from typing import Dict, Any, List
from vortex.core.scanner import BaseScanner
from vortex.core.http import SafeHTTPClient

logger = logging.getLogger("vortex.core.secrets")

class SecretScanner(BaseScanner):
    def __init__(self):
        self.patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
            "Generic Private Key": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
            "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
            "Hardcoded JWT": r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
        }

    def shannon_entropy(self, data: str) -> float:
        """Calculates the Shannon entropy of a string."""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Scans for secrets in the main page and linked JS files.
        """
        results = {
            "secrets_found": [],
            "count": 0
        }
        
        target = target if target.startswith("http") else f"http://{target}"
        
        async with SafeHTTPClient() as client:
            try:
                # 1. Fetch Main Page
                response = await client.get(target, timeout=10)
                if response.status != 200:
                    return results
                
                content = await response.text()
                
                # Scan Main Content
                self._scan_content(content, target, results)
                
                # 2. Extract JS Files (heuristic)
                # Find src=".../something.js"
                js_links = re.findall(r'src=["\'](.*?\.js)["\']', content)
                
                for link in js_links[:5]: # Limit to 5 JS files to avoid blowout
                    if not link.startswith("http"):
                        # Handle relative links
                        base = target.rstrip("/")
                        if link.startswith("/"):
                             js_url = f"{base}{link}"
                        else:
                             js_url = f"{base}/{link}"
                    else:
                        js_url = link
                        
                    try:
                        js_resp = await client.get(js_url, timeout=5)
                        if js_resp.status == 200:
                            js_content = await js_resp.text()
                            self._scan_content(js_content, js_url, results)
                    except Exception:
                        pass
                        
            except Exception as e:
                logger.debug(f"Secret scan error: {e}")
                results["error"] = str(e)

        results["count"] = len(results["secrets_found"])
        return results

    def _scan_content(self, content: str, url: str, results: Dict[str, Any]):
        for name, pattern in self.patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                secret = match.group(0)
                # Entropy Filter (heuristic: usually > 3.5 for good keys)
                entropy = self.shannon_entropy(secret)
                
                # JWTs are long, skip entropy check for them or use diff threshold
                if name == "Hardcoded JWT" or entropy > 3:
                     # Redact
                     redacted = secret[:4] + "*" * (len(secret)-8) + secret[-4:] if len(secret) > 8 else "****"
                     
                     results["secrets_found"].append({
                         "type": name,
                         "location": url,
                         "snippet": redacted,
                         "entropy": round(entropy, 2)
                     })
