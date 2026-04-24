import uuid
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from .schemas import RBISessionRequest, RBISessionResponse

logger = logging.getLogger(__name__)

class KasmClient:
    """Interface for managing Kasm Workspaces Remote Browser Isolation sessions."""
    async def create_session(self, request: RBISessionRequest) -> RBISessionResponse:
        raise NotImplementedError

class RealKasmClient(KasmClient):
    """Implementation using the official Kasm Workspaces API."""
    def __init__(self, api_url: str, api_key: str, api_secret: str):
        self.api_url = api_url
        self.api_key = api_key
        self.api_secret = api_secret

    async def create_session(self, request: RBISessionRequest) -> RBISessionResponse:
        # In a real implementation, this would make a request to the Kasm API
        # to provision a new session for the given browser and return the cast URL.
        logger.warning("RealKasmClient not fully implemented without actual Kasm infrastructure.")
        return RBISessionResponse(
            session_id=str(uuid.uuid4()),
            cast_url="about:blank",
            status="error",
            expires_at=datetime.now(timezone.utc)
        )

class SimulatedKasmClient(KasmClient):
    """Simulated Kasm Client for local development and UI testing."""
    async def create_session(self, request: RBISessionRequest) -> RBISessionResponse:
        # Simulate API delay
        time.sleep(0.5)
        
        session_id = str(uuid.uuid4())
        # For simulation, we'll return a cast URL that just echoes the requested URL safely 
        # or points to a safe placeholder. Since we want to show it in an iframe, 
        # we'll use a data URI or a safe public site like example.com wrapped securely.
        # Note: In a real Kasm setup, this URL points to a WebSocket stream of the container GUI.
        
        # We will use a safe representation for the simulation
        safe_url = f"https://example.com/?simulated_kasm_target={request.url}"
        
        return RBISessionResponse(
            session_id=session_id,
            cast_url=safe_url,
            status="active",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )

def get_kasm_client(mode: str = "simulated", api_url: Optional[str] = None, api_key: Optional[str] = None, api_secret: Optional[str] = None) -> KasmClient:
    """Factory function to get the appropriate Kasm Client."""
    if mode == "live" and api_url and api_key and api_secret:
        return RealKasmClient(api_url, api_key, api_secret)
    return SimulatedKasmClient()
