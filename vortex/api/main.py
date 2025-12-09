import asyncio
import os
import json
from typing import List
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
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

# Database Setup
# Use SQLite for local development default, Postgres for Docker
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///vortex.db")

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
            
            v_engine.register_scanner(HTTPScanner())
            
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

            results = await v_engine.scan_target(scan.target)
            
            scan.results = results
            scan.status = "completed"
            
        except Exception as e:
            scan.status = "failed"
            scan.results = {"error": str(e)}
            
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
