import asyncio
import os
import json
import logging
from redis import asyncio as aioredis
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from vortex.api.models import Scan
from vortex.core.engine import VortexEngine
# Import Scanners
from vortex.core.modules.network import PortScanner
from vortex.core.modules.http import HTTPScanner
from vortex.core.modules.cloud import CloudScanner
from vortex.core.modules.iot import IoTScanner
from vortex.core.modules.graphql import GraphQLScanner
from vortex.core.modules.pentest import PentestEngine
from vortex.core.modules.recon import CTScanner
from vortex.core.modules.secrets import SecretScanner
from vortex.core.modules.api_fuzzer import APIScanner
from vortex.integrations.defectdojo import DefectDojoClient

# Config
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///vortex.db")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vortex.worker")

engine = create_async_engine(DATABASE_URL, echo=False, future=True)

async def process_scan(scan_id: int):
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        logger.info(f"Drone picked up scan {scan_id} for target {scan.target}")
        
        scan.status = "running"
        session.add(scan)
        await session.commit()
        
        try:
            # Init Engine
            v_engine = VortexEngine()
            opts = scan.options or {}
            
            # 1. Always Run Recon (Passive)
            v_engine.register_scanner(CTScanner())
            
            # 2. Configurable Scanners
            v_engine.register_scanner(HTTPScanner())
            
            if opts.get("secrets", False):
                v_engine.register_scanner(SecretScanner())
                
            if opts.get("api_fuzz", False):
                v_engine.register_scanner(APIScanner())

            port_list = None
            if opts.get("ports"):
                p_arg = opts.get("ports")
                if isinstance(p_arg, str):
                    port_list = [int(p) for p in p_arg.split(",")]
                elif isinstance(p_arg, list):
                    port_list = p_arg
            
            v_engine.register_scanner(PortScanner(ports=port_list))
            
            if opts.get("cloud", False):
                v_engine.register_scanner(CloudScanner())
            
            if opts.get("iot", False):
                v_engine.register_scanner(IoTScanner())
                
            if opts.get("graphql", False):
                v_engine.register_scanner(GraphQLScanner())
                
            if opts.get("auto_exploit", False):
                v_engine.register_scanner(PentestEngine())

            # Execution
            logger.info("Executing scan logic...")
            results = await v_engine.scan_target(scan.target)
            
            scan.results = results
            scan.status = "completed"
            logger.info(f"Scan {scan_id} completed successfully")
            
            # DefectDojo Integration (Worker side handles this too)
            if opts.get("defect_dojo_url") and opts.get("defect_dojo_key") and opts.get("engagement_id"):
                 try:
                     dd_client = DefectDojoClient(opts.get("defect_dojo_url"), opts.get("defect_dojo_key"))
                     await dd_client.import_scan(results, int(opts.get("engagement_id")))
                 except Exception as e:
                     logger.error(f"DefectDojo error: {e}")

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            scan.status = "failed"
            scan.results = {"error": str(e)}
        finally:
            session.add(scan)
            await session.commit()

async def worker():
    logger.info("Vortex Drone Online. Waiting for tasks...")
    redis = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    
    while True:
        try:
            # Blocking pop
            task = await redis.blpop("vortex_tasks", timeout=5)
            if task:
                _, scan_id = task
                await process_scan(int(scan_id))
        except Exception as e:
            logger.error(f"Worker loop error: {e}")
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(worker())
