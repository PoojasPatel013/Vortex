import asyncio
import os
import json
from typing import List
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlmodel import SQLModel, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from vortex.api.models import Scan, ScanCreate, ScanRead
from vortex.core.engine import VortexEngine
from vortex.core.modules.network import PortScanner
from vortex.core.modules.http import HTTPScanner
from vortex.core.modules.cloud import CloudScanner
from vortex.core.modules.iot import IoTScanner
from vortex.core.modules.graphql import GraphQLScanner
from vortex.core.modules.pentest import PentestEngine
from vortex.integrations.defectdojo import DefectDojoClient
from vortex.core.reporter import SARIFReporter
from vortex.core.modules.recon import CTScanner
from vortex.core.modules.secrets import SecretScanner
from vortex.core.modules.api_fuzzer import APIScanner
from redis import asyncio as aioredis

# Database Setup
# Use SQLite for local development default, Postgres for Docker
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///vortex.db")
REDIS_URL = os.getenv("REDIS_URL")

engine = create_async_engine(DATABASE_URL, echo=True, future=True)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

async def get_session():
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session

app = FastAPI(title="Vortex API", version="0.1.0")

# Setup Static & Templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.on_event("startup")
async def on_startup():
    retries = 5
    wait = 2
    for i in range(retries):
        try:
            await init_db()
            print("Database connected successfully.")
            return
        except Exception as e:
            print(f"Database connection failed ({i+1}/{retries}): {e}")
            if i < retries - 1:
                await asyncio.sleep(wait)
                wait *= 2  # Exponential backoff
            else:
                raise e

async def run_scan_task(scan_id: int):
    # Create a new session for this task
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return
            
        scan.status = "running"
        session.add(scan)
        await session.commit()
        
        try:
            # Run Vortex Engine
            v_engine = VortexEngine()
            
            # Configure Scanners (Based on Options)
            opts = scan.options or {}
            
            # 1. CT Recon (Always good to have if enabled, or default)
            # Check if toggled or just run it
            if opts.get("recon", True): # Default to true
                 v_engine.register_scanner(CTScanner())
            
            # Default Scanners
            v_engine.register_scanner(HTTPScanner())
            
            if opts.get("secrets", False):
                v_engine.register_scanner(SecretScanner())
                
            if opts.get("api_fuzz", False):
                v_engine.register_scanner(APIScanner())
            
            port_list = None
            if opts.get("ports"):
                 # Handle comma separated string or list
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
            
            # Auto Exploit (Polyglot)
            if opts.get("auto_exploit", False):
                 v_engine.register_scanner(PentestEngine())

            # Run with timeout to prevent zombies
            results = await asyncio.wait_for(v_engine.scan_target(scan.target), timeout=600)
            
            scan.results = results
            scan.status = "completed"
            
            # Post-Scan Actions: DefectDojo Import
            if opts.get("defect_dojo_url") and opts.get("defect_dojo_key") and opts.get("engagement_id"):
                try:
                    logger.info("Triggering DefectDojo Import...")
                    dd_client = DefectDojoClient(opts.get("defect_dojo_url"), opts.get("defect_dojo_key"))
                    await dd_client.import_scan(results, int(opts.get("engagement_id")))
                except Exception as dd_e:
                    logger.error(f"DefectDojo Integration Failed: {dd_e}")
                    # Don't fail the scan status, just log
            
        except asyncio.TimeoutError:
             scan.status = "failed"
             scan.results = {"error": "Scan timed out (300s limit)"}
        except Exception as e:
            print(f"Scan Task Error: {e}")
            scan.status = "failed"
            scan.results = {"error": str(e)}
        finally:
            session.add(scan)
            await session.commit()

@app.post("/scans", response_model=ScanRead)
async def create_scan(scan_in: ScanCreate, background_tasks: BackgroundTasks, session: AsyncSession = Depends(get_session)):
    scan = Scan(
        target=scan_in.target,
        scan_type=scan_in.scan_type,
        options=scan_in.options,
        status="pending"
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    
    # Distributed (Drone) Mode vs Local
    if REDIS_URL:
        try:
            redis = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
            await redis.rpush("vortex_tasks", str(scan.id))
            print(f"Dispatched Scan {scan.id} to Drone Grid")
            await redis.close()
        except Exception as e:
            print(f"Redis dispatch failed: {e}. Falling back to local.")
            background_tasks.add_task(run_scan_task, scan.id)
    else:
        background_tasks.add_task(run_scan_task, scan.id)
        
    return scan

@app.get("/scans", response_model=List[ScanRead])
async def list_scans(offset: int = 0, limit: int = 100, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Scan).offset(offset).limit(limit))
    scans = result.scalars().all()
    return scans

@app.get("/scans/{scan_id}", response_model=ScanRead)
async def read_scan(scan_id: int, session: AsyncSession = Depends(get_session)):
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int, session: AsyncSession = Depends(get_session)):
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await session.delete(scan)
    await session.commit()
    return {"ok": True}

@app.get("/scans/{scan_id}/sarif")
async def export_scan_sarif(scan_id: int, session: AsyncSession = Depends(get_session)):
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if not scan.results:
        return {"error": "Scan has no results yet"}

    reporter = SARIFReporter()
    sarif_data = reporter.convert_scan_results(scan.results, scan.target)
    
    return sarif_data
