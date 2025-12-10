from typing import List, Dict, Any

class ComplianceEngine:
    """
    Maps technical findings to Business Risk/Compliance Frameworks.
    Supported: PCI-DSS, ISO 27001, GDPR, HIPAA, NIST CSF.
    """
    
    COMPLIANCE_MAP = {
        "Open Port": {
            "PCI-DSS": ["Req 1.3: Prohibit direct public access"],
            "ISO 27001": ["A.13.1.1: Network Controls"],
            "NIST CSF": ["PR.AC-5: Network Integrity"]
        },
        "Missing Security Header": {
            "PCI-DSS": ["Req 6.5.10: Broken Access Control"],
            "OWASP": ["A05:2021-Security Misconfiguration"],
            "GDPR": ["Art 32: Security of Processing"]
        },
        "Public S3 Bucket": {
            "HIPAA": ["§164.312(a)(1): Access Control"],
            "GDPR": ["Art 32: Data Leakage Protection"],
            "PCI-DSS": ["Req 3.4: Protect Stored Data"]
        },
        "Weak SSL/TLS": {
            "PCI-DSS": ["Req 4.1: Strong Cryptography"],
            "NIST CSF": ["PR.DS-2: Data-in-Transit Protection"]
        },
        "Default Credentials": {
            "PCI-DSS": ["Req 2.1: Changing Default Defaults"],
            "ISO 27001": ["A.9.4.3: Password Management"]
        },
        "SQL Injection": {
            "PCI-DSS": ["Req 6.5.1: Injection Flaws"],
            "OWASP": ["A03:2021-Injection"]
        },
        "Cross-Site Scripting (XSS)": {
            "PCI-DSS": ["Req 6.5.7: XSS"],
            "OWASP": ["A03:2021-Injection"]
        },
         "Shadow API": {
            "ISO 27001": ["A.12.6.1: Tech Vuln Mgmt"],
            "OWASP API": ["API9:2019 Improper Assets Management"]
        }
    }

    def map_finding(self, finding_type: str, severity: str) -> Dict[str, List[str]]:
        """
        Enrich a finding with compliance tags.
        """
        # normalize
        key = "Generic"
        finding_lower = finding_type.lower()
        
        # Heuristic Matching
        if "port" in finding_lower:
            key = "Open Port"
        elif "header" in finding_lower:
            key = "Missing Security Header"
        elif "bucket" in finding_lower or "s3" in finding_lower:
            key = "Public S3 Bucket"
        elif "ssl" in finding_lower or "tls" in finding_lower:
            key = "Weak SSL/TLS"
        elif "sql" in finding_lower:
            key = "SQL Injection"
        elif "xss" in finding_lower:
            key = "Cross-Site Scripting (XSS)"
        elif "api" in finding_lower:
            key = "Shadow API"
            
        return self.COMPLIANCE_MAP.get(key, {})

    def enrich_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Traverses scan results and injects a 'compliance' field into each finding.
        """
        total_violations = {"PCI-DSS": 0, "GDPR": 0, "ISO 27001": 0}
        
        # Helper to process a list of findings
        def process_list(finding_list):
            for finding in finding_list:
                ftype = finding.get("type") or finding.get("name") or "Unknown"
                sev = finding.get("severity", "Info")
                
                compliance = self.map_finding(ftype, sev)
                if compliance:
                    finding["compliance"] = compliance
                    # Count stats
                    for framework in compliance:
                        if framework in total_violations:
                            total_violations[framework] += 1
                            
        # 1. Process standard Vulnerabilities list
        if "vulnerabilities" in results:
             process_list(results["vulnerabilities"])
             
        # 2. Process Module Specifics
        # Cloud
        if "CloudScanner" in results:
             # Adapt CloudScanner format to generic if needed, 
             # usually it returns a dict, let's assume we map its internal list
             if "s3_buckets" in results["CloudScanner"]:
                  # These aren't standard findings dicts usually, so we might need manual handling
                  # For MVP, let's skip deep structure mod unless standardized
                  pass

        # Add Summary
        results["compliance_summary"] = total_violations
        return results
