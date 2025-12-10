import json
from typing import Dict, Any, List

class SARIFReporter:
    def __init__(self, tool_name: str = "Vortex", tool_version: str = "0.1.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.rules = []
        self.results = []
        self.rule_ids = set()

    def _get_or_create_rule(self, rule_id: str, name: str, description: str) -> str:
        if rule_id not in self.rule_ids:
            self.rules.append({
                "id": rule_id,
                "name": name,
                "shortDescription": {
                    "text": description
                },
                "fullDescription": {
                    "text": description
                },
                "properties": {
                    "tags": ["security", "vortex"]
                }
            })
            self.rule_ids.add(rule_id)
        return rule_id

    def add_result(self, scanner_name: str, vulnerability_type: str, severity: str, message: str, location: str):
        rule_id = f"{scanner_name.upper()}_{vulnerability_type.replace(' ', '_').upper()}"
        self._get_or_create_rule(rule_id, vulnerability_type, f"{vulnerability_type} detected by {scanner_name}")
        
        sarif_level = "warning"
        if severity.lower() in ["high", "critical"]:
            sarif_level = "error"
        elif severity.lower() in ["info", "low"]:
            sarif_level = "note"

        self.results.append({
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": message
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": location
                        }
                    }
                }
            ]
        })

    def convert_scan_results(self, scan_results: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Parses Vortex internal JSON results and populates SARIF results.
        """
        # Module A: HTTP
        if "HTTPScanner" in scan_results:
            http = scan_results["HTTPScanner"]
            # Example: Missing security headers
            headers = http.get("headers", {})
            if "X-Content-Type-Options" not in headers:
                self.add_result(
                    "HTTPScanner", 
                    "Missing Security Header", 
                    "Low", 
                    "The 'X-Content-Type-Options' header is missing.", 
                    target
                )

        # Module B: Cloud
        if "CloudScanner" in scan_results:
            cloud = scan_results["CloudScanner"]
            for bucket in cloud.get("s3_buckets", []):
                if bucket.get("code") == 200:
                    self.add_result(
                        "CloudScanner",
                        "Public S3 Bucket",
                        "High",
                        f"Public S3 bucket found: {bucket['url']}",
                        bucket['url']
                    )

        # Module C: IoT
        if "IoTScanner" in scan_results:
            iot = scan_results["IoTScanner"]
            if iot.get("mqtt_exposed"):
                self.add_result(
                    "IoTScanner",
                    "MQTT Anonymous Access",
                    "High",
                    iot.get("details", "Anonymous MQTT allowed"),
                    f"mqtt://{target}:1883"
                )

        # Module D: Pentest Engine (XSS etc)
        if "PentestEngine" in scan_results:
             pentest = scan_results["PentestEngine"]
             for vuln in pentest.get("vulnerabilities", []):
                 self.add_result(
                     "PentestEngine",
                     vuln.get("type", "Unknown Vulnerability"),
                     "High", # Defaulting to high for detected exploits
                     f"{vuln.get('description', 'Vulnerability found')} Evidence: {vuln.get('evidence', '')}",
                     target
                 )

        return self._generate_report()

    def _generate_report(self) -> Dict[str, Any]:
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "rules": self.rules
                        }
                    },
                    "results": self.results
                }
            ]
        }
