from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class RBISessionRequest(BaseModel):
    url: str = Field(..., description="The URL to open in the isolated browser")
    browser_type: str = Field("chrome", description="Browser type (chrome, firefox, tor)")
    resolution: str = Field("1920x1080", description="Viewport resolution")

class RBISessionResponse(BaseModel):
    session_id: str
    cast_url: str = Field(..., description="The secure WebSocket/WebRTC streaming URL to embed")
    status: str = Field("active", description="Session status")
    expires_at: datetime

class SanitizationRequest(BaseModel):
    file_name: str = Field(..., description="Name of the file being sanitized")
    file_size: int = Field(..., description="Size of the file in bytes")

class SanitizationResponse(BaseModel):
    task_id: str
    status: str = Field(..., description="Status of the sanitization (processing, safe, error)")
    safe_file_url: Optional[str] = Field(None, description="URL to download the sanitized PDF")
    original_sha256: str
    safe_sha256: Optional[str] = None
    message: str = ""
