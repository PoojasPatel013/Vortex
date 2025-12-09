import aiohttp
import asyncio
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("vortex.core.http")

class SafeHTTPClient:
    """
    A wrapper around aiohttp.ClientSession that handles rate limiting 
    and exponential backoff for 429/403 responses.
    """
    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        self._external_session = session is not None
        self.session = session or aiohttp.ClientSession()
        self.max_retries = 3
        self.base_delay = 1.0

    async def __aenter__(self):
        if not self._external_session:
             # Disable SSL verification for pentesting tools
            connector = aiohttp.TCPConnector(ssl=False)
            self.session = aiohttp.ClientSession(connector=connector)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if not self._external_session and self.session:
            await self.session.close()

    async def request(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        retries = 0
        delay = self.base_delay
        
        while retries <= self.max_retries:
            try:
                response = await self.session.request(method, url, **kwargs)
                
                if response.status == 429 or response.status == 403:
                    # Smart Rate Limiting Logic
                    # If we get 429 (Too Many Requests) or 403 (Forbidden - could be WAF blocking)
                    # We accept that 403 might be legitimate, but often it's a rate limit in disguise.
                    # We'll retry 429s aggressively, and 403s cautiously.
                    
                    if response.status == 403 and retries > 0:
                        # If we already retried a 403 and failed again, it's likely a real block/perm issue.
                        return response
                        
                    logger.warning(f"Rate limited ({response.status}) on {url}. Retrying in {delay}s...")
                    await asyncio.sleep(delay)
                    retries += 1
                    delay *= 2 # Exponential Backoff
                    continue
                    
                return response
                
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"Request failed: {e}. Retrying...")
                await asyncio.sleep(delay)
                retries += 1
                delay *= 2
                
        # If we run out of retries, perform one final attempt (or raise/return error)
        # Here we just return the result of the final attempt or raise
        return await self.session.request(method, url, **kwargs)

    async def get(self, url: str, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs):
        return await self.request("HEAD", url, **kwargs)
