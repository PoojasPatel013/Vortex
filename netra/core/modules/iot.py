import asyncio
import logging
from typing import Dict, Any
from gmqtt import Client as MQTTClient
from vortex.core.scanner import BaseScanner

logger = logging.getLogger("vortex.core.iot")

class IoTScanner(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Checks for anonymous MQTT access on port 1883.
        """
        results = {
            "mqtt_exposed": False,
            "details": "Port 1883 closed or filtered"
        }
        
        client = MQTTClient("vortex-scanner")
        
        connected = False
        
        def on_connect(client, flags, rc, properties):
            nonlocal connected
            if rc == 0:
                connected = True
                
        client.on_connect = on_connect
        
        try:
            # Attempt connection with NO credentials
            await client.connect(target, port=1883, keepalive=5)
            # Short wait to allow handshake
            await asyncio.sleep(2)
            
            if connected:
                results["mqtt_exposed"] = True
                results["details"] = "Anonymous login allowed on port 1883 (High Severity)"
                await client.disconnect()
            
        except Exception as e:
            logger.debug(f"MQTT connection failed for {target}: {e}")
            results["details"] = str(e)
            
        return results
