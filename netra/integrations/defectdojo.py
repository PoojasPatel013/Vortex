import aiohttp
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)

class DefectDojoClient:
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Token {api_key}",
            "Content-Type": "application/json"
        }

    async def import_scan(self, scan_results: dict, engagement_id: int, scan_type: str = "Vortex Scan"):
        """
        Imports scan results into DefectDojo.
        Note: This requires transforming Vortex results into a format DefectDojo accepts (e.g., Generic Findings Import)
        """
        endpoint = f"{self.url}/api/v2/import-scan/"
        
        # Transform results to Generic Findings Format (simplified)
        findings = []
        date = datetime.now().strftime("%Y-%m-%d")
        
        # Process Pentest Results
        if "PentestEngine" in scan_results:
            for vuln in scan_results["PentestEngine"].get("vulnerabilities", []):
                findings.append({
                    "title": vuln["type"],
                    "description": vuln["description"],
                    "severity": vuln["severity"],
                    "date": date,
                    "active": True,
                    "verified": True
                })
        
        # If no findings, nothing to import, or import as empty
        if not findings:
            logger.info("No findings to import to DefectDojo")
            return
            
        # Prepare generic findings payload
        # In Generic Findings Import, we upload a JSON file.
        
        scan_date = datetime.now().strftime("%Y-%m-%d")
        payload = {
            "findings": findings,
            "date": scan_date,
            "engagement_id": engagement_id,
            "scan_type": scan_type
        }
        
        # We need to construct a "fake" file for the upload
        file_content = json.dumps(payload)
        
        data = aiohttp.FormData()
        data.add_field("engagement", str(engagement_id))
        data.add_field("scan_type", "Generic Findings Import")
        data.add_field("verified", "true")
        data.add_field("active", "true")
        data.add_field("minimum_severity", "Low")
        data.add_field("skip_duplicates", "true")
        data.add_field("close_old_findings", "false")
        
        # Add the file
        data.add_field("file", file_content, filename="vortex_results.json", content_type="application/json")
        
        try:
            async with aiohttp.ClientSession(headers={"Authorization": f"Token {self.api_key}"}) as session:
                async with session.post(endpoint, data=data) as resp:
                    if resp.status == 201:
                        logger.info(f"Successfully imported scan to DefectDojo. ID: {engagement_id}")
                        return {"ok": True, "status": resp.status}
                    else:
                        resp_text = await resp.text()
                        logger.error(f"Failed to import to DefectDojo: {resp.status} - {resp_text}")
                        return {"ok": False, "status": resp.status, "error": resp_text}
        except Exception as e:
            logger.error(f"DefectDojo Connection Error: {e}")
            return {"ok": False, "error": str(e)}
