import asyncio
import logging
from typing import List, Dict, Any
from vortex.core.scanner import BaseScanner

logger = logging.getLogger("vortex.core")

class VortexEngine:
    def __init__(self):
        self.scanners: List[BaseScanner] = []
        self.results: Dict[str, Any] = {}

    def register_scanner(self, scanner: BaseScanner):
        self.scanners.append(scanner)

    async def scan_target(self, target: str) -> Dict[str, Any]:
        """
        Orchestrates the scan for a given target.
        Runs all registered scanners concurrently.
        """
        logger.info(f"Starting scan for target: {target}")
        self.results[target] = {}
        
        tasks = []
        for scanner in self.scanners:
            tasks.append(scanner.scan(target))
        
        # Run all scanners concurrently
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for scanner, result in zip(self.scanners, scan_results):
            scanner_name = scanner.__class__.__name__
            if isinstance(result, Exception):
                logger.error(f"Scanner {scanner_name} failed: {result}")
                self.results[target][scanner_name] = {"error": str(result)}
            else:
                self.results[target][scanner_name] = result
                
        # Integrate Compliance Engine
        from vortex.core.compliance import ComplianceEngine
        try:
            comp_engine = ComplianceEngine()
            # This mutates the results dictionary in place
            comp_engine.enrich_report(self.results[target])
        except Exception as e:
            logger.error(f"Compliance Engine failed: {e}")

        logger.info(f"Scan completed for target: {target}")
        return self.results[target]
