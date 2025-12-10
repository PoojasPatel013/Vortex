import asyncio
import socket
from typing import Dict, Any, List
from vortex.core.scanner import BaseScanner

class PortScanner(BaseScanner):
    def __init__(self, ports: List[int] = None, concurrency: int = 100):
        self.ports = ports or [21, 22, 80, 443, 3000, 8000, 8080] # Default common ports
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)

    async def check_port(self, target: str, port: int) -> int:
        async with self.semaphore:
            try:
                # Resolve target to IP to avoid DNS blocking
                # But asyncio.open_connection handles it.
                # We use a short timeout for port scanning
                future = asyncio.open_connection(target, port)
                reader, writer = await asyncio.wait_for(future, timeout=1.0)
                writer.close()
                await writer.wait_closed()
                return port
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

    async def scan(self, target: str) -> Dict[str, Any]:
        # Strip protocol if present for port scanning
        host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        
        tasks = [self.check_port(host, port) for port in self.ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [port for port in results if port is not None]
        return {"open_ports": open_ports}
