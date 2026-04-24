from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class SandboxExecutionRequest(BaseModel):
    code: str = Field(..., description="The code snippet to execute")
    language: str = Field("python", description="Programming language (e.g., python, javascript)")
    dependencies: List[str] = Field(default_factory=list, description="List of package dependencies to install")
    timeout_seconds: int = Field(60, description="Execution timeout in seconds")
    network_access: str = Field("restricted", description="Network access level: 'restricted', 'none', or 'full'")
    allowed_domains: List[str] = Field(default_factory=list, description="List of domains allowed if restricted")

class SandboxExecutionResult(BaseModel):
    execution_id: str
    status: str = Field(..., description="'success', 'error', or 'timeout'")
    stdout: str
    stderr: str
    execution_time_ms: int
    error_message: Optional[str] = None
    files_created: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
