import aiohttp
import logging
from typing import Dict, Any
from vortex.core.scanner import BaseScanner

logger = logging.getLogger("vortex.core.cloud")

class CloudScanner(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Checks for public S3 buckets associated with the target name.
        """
        results = {
            "s3_buckets": []
        }
        
        # Simple heuristic: check if target name is a bucket
        # In a real scenario, we might permute names (e.g. target-backup, target-dev)
        bucket_names = [
            target,
            f"www.{target}",
            f"{target}-backup",
            f"{target}-dev",
            f"{target}-assets"
        ]
        
        # Clean domain names to get potential bucket names 
        # e.g. example.com -> example 
        base_name = target.split(".")[0]
        if base_name != target:
             bucket_names.append(base_name)
             bucket_names.append(f"{base_name}-assets")
             bucket_names.append(f"{base_name}-backup")

        async with aiohttp.ClientSession() as session:
            for bucket in set(bucket_names):
                url = f"https://{bucket}.s3.amazonaws.com"
                try:
                    async with session.head(url, timeout=5) as response:
                        if response.status == 200:
                            results["s3_buckets"].append({
                                "bucket": bucket,
                                "url": url,
                                "status": "Publicly Listable (Dangerous)",
                                "code": 200
                            })
                        elif response.status == 403:
                            results["s3_buckets"].append({
                                "bucket": bucket,
                                "url": url,
                                "status": "Exists but Private (Info)",
                                "code": 403
                            })
                except Exception as e:
                    logger.debug(f"Failed to check bucket {bucket}: {e}")
                    
        return results
