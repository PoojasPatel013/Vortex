import logging
import asyncio
import aiohttp
import re
from typing import Dict, Any, List
from netra.core.scanner import BaseScanner
from netra.core.http import SafeHTTPClient

logger = logging.getLogger("netra.core.threat")

class ThreatScanner(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Threat Intel (Real Logic): Email Security (SPF/DMARC) & Exposure Config.
        No API keys required.
        """
        results = {
            "threats_detected": 0,
            "checks_performed": ["SPF Record", "DMARC Policy", "Robots.txt Exposure", "Security.txt"],
            "vulnerabilities": []
        }
        
        # Normalize to domain
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        base_url = f"http://{domain}" # Default to http for config checks if target doesn't specify
        if target.startswith("http"):
             base_url = target
        
        logger.info(f"Running Logic-Based Threat Scan for {domain}")

        # Check if domain is actually an IP
        is_ip = False
        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            is_ip = False
        
        async with SafeHTTPClient() as client:
            # 1. SPF Check (Skipped for IPs)
            if not is_ip:
                spf_vuln = await self._check_spf(client, domain)
                if spf_vuln:
                    results["threats_detected"] += 1
                    results["vulnerabilities"].append(spf_vuln)
                
                # 2. DMARC Check (Skipped for IPs)
                dmarc_vuln = await self._check_dmarc(client, domain)
                if dmarc_vuln:
                    results["threats_detected"] += 1
                    results["vulnerabilities"].append(dmarc_vuln)
            else:
                logger.info("Skipping SPF/DMARC checks for IP address target.")
            
            # 3. Robots.txt Analysis (Valid for IPs too)
            robots_vuln = await self._check_robots(client, base_url)
            if robots_vuln:
                results["threats_detected"] += 1
                results["vulnerabilities"].append(robots_vuln)

            # 4. Security.txt Check
            sec_vuln = await self._check_security_txt(client, base_url)
            if sec_vuln:
               results["threats_detected"] += 1
               results["vulnerabilities"].append(sec_vuln)

        return results

    async def _query_dns_txt(self, client, hostname: str) -> List[str]:
        """Query DNS TXT using Google DoH"""
        url = f"https://dns.google/resolve?name={hostname}&type=TXT"
        try:
            resp = await client.get(url)
            if resp.status == 200:
                data = await resp.json()
                if "Answer" in data:
                    # DNS answers often come quoted e.g. "v=spf1..."
                    return [ans["data"].strip('"') for ans in data["Answer"]]
        except Exception as e:
            logger.warning(f"DNS lookup failed for {hostname}: {e}")
        return []

    async def _check_spf(self, client, domain: str):
        records = await self._query_dns_txt(client, domain)
        spf_record = next((r for r in records if "v=spf1" in r), None)
        
        if not spf_record:
            return {
                "type": "Missing SPF Record",
                "severity": "Medium",
                "details": "Domain has no SPF record. Spammers can easily spoof emails from this domain.",
                "solution": "Add a TXT record: v=spf1 mx ~all"
            }
        elif "+all" in spf_record:
             return {
                "type": "Weak SPF Record",
                "severity": "High",
                "details": "SPF record allows anyone check (+all). This renders SPF useless.",
                "evidence": spf_record
            }
        return None

    async def _check_dmarc(self, client, domain: str):
        records = await self._query_dns_txt(client, f"_dmarc.{domain}")
        dmarc_record = next((r for r in records if "v=DMARC1" in r), None)
        
        if not dmarc_record:
             return {
                "type": "Missing DMARC Record",
                "severity": "Medium",
                "details": "No DMARC policy found. Email spoofing is harder to detect/block.",
                "solution": "Add _dmarc TXT record with at least p=none (monitoring)."
            }
        elif "p=none" in dmarc_record:
             return {
                "type": "DMARC Policy Not Enforced",
                "severity": "Low",
                "details": "DMARC policy is set to 'none'. Spoofed emails are not rejected.",
                "evidence": dmarc_record
            }
        return None

    async def _check_robots(self, client, base_url: str):
        url = f"{base_url.rstrip('/')}/robots.txt"
        try:
            resp = await client.get(url)
            if resp.status == 200:
                text = await resp.text()
                # Check for sensitive disallows
                sensitive = ["admin", "backup", "db", "config", "debug", "private"]
                found = []
                for line in text.splitlines():
                    if "disallow:" in line.lower():
                        rule = line.split(":", 1)[1].strip()
                        if any(s in rule.lower() for s in sensitive):
                            found.append(rule)
                
                if found:
                    return {
                        "type": "Sensitive Paths in Robots.txt",
                        "severity": "Low",
                        "details": "Robots.txt reveals sensitive directory scope.",
                        "evidence": f"Disallowed paths: {', '.join(found[:5])}"
                    }
        except Exception:
            pass
        return None
        
    async def _check_security_txt(self, client, base_url: str):
         url = f"{base_url.rstrip('/')}/.well-known/security.txt"
         try:
            resp = await client.get(url)
            if resp.status != 200:
                 return {
                    "type": "Missing Security.txt",
                    "severity": "Info",
                    "details": "No security.txt found. Logic-based scanners cannot report findings easily.",
                    "solution": "Add a security.txt file to define your vulnerability disclosure policy."
                }
         except Exception:
             pass
         return None
