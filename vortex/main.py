import asyncio
import typer
import json
import uvicorn
from typing import Optional
from vortex.core.engine import VortexEngine
from vortex.core.modules.network import PortScanner
from vortex.core.modules.http import HTTPScanner
from vortex.core.modules.pentest import PentestEngine
from vortex.core.modules.cloud import CloudScanner
from vortex.core.modules.iot import IoTScanner
from vortex.core.modules.graphql import GraphQLScanner
from vortex.core.reporter import SARIFReporter

app = typer.Typer()

@app.command()
def version():
    """
    Show version.
    """
    print("Vortex v0.1.0")

@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Host to bind to"),
    port: int = typer.Option(8000, help="Port to bind to")
):
    """
    Start the API server.
    """
    print(f"Starting Vortex API on {host}:{port}")
    uvicorn.run("vortex.api.main:app", host=host, port=port, reload=True)

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL"), 
    auto_exploit: bool = typer.Option(False, "--auto-exploit", help="Enable auto exploitation"), 
    ports: str = typer.Option(None, "--ports", "-p", help="Comma separated list of ports"),
    cloud: bool = typer.Option(False, "--cloud", help="Enable Cloud Infrastructure Scanner"),
    iot: bool = typer.Option(False, "--iot", help="Enable IoT Protocol Fuzzer"),
    graphql: bool = typer.Option(False, "--graphql", help="Enable GraphQL Introspection Scanner"),
    export_sarif: str = typer.Option(None, "--export-sarif", help="Export results to SARIF file (e.g. results.sarif)")
):
    """
    Run a scan against a target.
    """
    async def run():
        engine = VortexEngine()
        
        # Configure Port Scanner
        port_list = None
        if ports:
            port_list = [int(p) for p in ports.split(",")]
        engine.register_scanner(PortScanner(ports=port_list))
        
        engine.register_scanner(HTTPScanner())
        
        if cloud:
            engine.register_scanner(CloudScanner())
            
        if iot:
            engine.register_scanner(IoTScanner())
            
        if graphql:
            engine.register_scanner(GraphQLScanner())
        
        if auto_exploit:
            engine.register_scanner(PentestEngine())
            
        results = await engine.scan_target(target)
        print(json.dumps(results, indent=2))
        
        if export_sarif:
            reporter = SARIFReporter()
            sarif_report = reporter.convert_scan_results(results, target)
            with open(export_sarif, "w") as f:
                json.dump(sarif_report, f, indent=2)
            print(f"\n[+] SARIF report exported to {export_sarif}")

    asyncio.run(run())

if __name__ == "__main__":
    app()
