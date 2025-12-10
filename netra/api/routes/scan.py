from fastapi import APIRouter, BackgroundTasks, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from vortex.core.engine import VortexEngine
from vortex.core.modules.network import PortScanner
from vortex.core.modules.http import HTTPScanner
from vortex.core.modules.pentest import PentestEngine
from vortex.core.database import get_session, Scan, Vulnerability
from sqlmodel import Session, select
import asyncio

router = APIRouter()

# Global engine instance (simple in-memory state for now)
engine = VortexEngine()
# Register default scanners
engine.register_scanner(PortScanner())
engine.register_scanner(HTTPScanner())
engine.register_scanner(PentestEngine())

class ScanRequest(BaseModel):
    target: str
    modules: Optional[List[str]] = ["network", "http"]

async def run_scan_background(scan_id: int, target: str):
    # This function runs in the background
    # It performs the scan and updates the DB
    results = await engine.scan_target(target)
    
    # Update DB
    from vortex.core.database import engine as db_engine
    with Session(db_engine) as session:
        scan = session.get(Scan, scan_id)
        if scan:
            scan.status = "completed"
            session.add(scan)
            
            # Save Vulnerabilities
            # Flatten results from different modules
            for module, data in results.items():
                if module == "PortScanner":
                    for port in data.get("open_ports", []):
                        session.add(Vulnerability(scan_id=scan_id, type="Open Port", severity="Info", description=f"Port {port} is open"))
                elif module == "HTTPScanner":
                    if "server" in data:
                         session.add(Vulnerability(scan_id=scan_id, type="Tech Stack", severity="Info", description=f"Server: {data['server']}"))
                elif module == "PentestEngine":
                    for vuln in data.get("vulnerabilities", []):
                        session.add(Vulnerability(
                            scan_id=scan_id, 
                            type=vuln["type"], 
                            severity=vuln["severity"], 
                            description=vuln["description"],
                            evidence=vuln.get("evidence")
                        ))
            
            session.commit()

@router.post("/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    """
    Start a scan for a target.
    """
    # Create Scan Record
    scan = Scan(target=request.target, status="pending")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    
    background_tasks.add_task(run_scan_background, scan.id, request.target)
    return {"message": "Scan started", "target": request.target, "scan_id": scan.id}

@router.get("/results/{target}")
async def get_results(target: str, session: Session = Depends(get_session)):
    """
    Get results for a target (Latest scan).
    """
    # Find latest scan for target
    statement = select(Scan).where(Scan.target == target).order_by(Scan.timestamp.desc())
    results = session.exec(statement)
    scan = results.first()
    
    if not scan:
        return {"status": "not found"}
        
    # Get vulnerabilities
    vulns = session.exec(select(Vulnerability).where(Vulnerability.scan_id == scan.id)).all()
    
    # Format for frontend (backward compatibility)
    # We need to reconstruct the structure expected by the frontend
    # Or update the frontend. Let's reconstruct for now to keep it simple.
    
    formatted_results = {
        "status": scan.status,
        "scan_id": scan.id,
        "timestamp": scan.timestamp,
        "PortScanner": {"open_ports": []},
        "HTTPScanner": {"server": "Unknown", "tech_stack": []},
        "PentestEngine": {"vulnerabilities": []}
    }
    
    for v in vulns:
        if v.type == "Open Port":
            try:
                port = int(v.description.split(" ")[1])
                formatted_results["PortScanner"]["open_ports"].append(port)
            except: pass
        elif v.type == "Tech Stack":
             formatted_results["HTTPScanner"]["server"] = v.description.replace("Server: ", "")
        else:
             formatted_results["PentestEngine"]["vulnerabilities"].append({
                 "type": v.type,
                 "severity": v.severity,
                 "description": v.description,
                 "evidence": v.evidence
             })
             
    return formatted_results

@router.get("/history")
async def get_history(session: Session = Depends(get_session)):
    scans = session.exec(select(Scan).order_by(Scan.timestamp.desc()).limit(10)).all()
    return scans
