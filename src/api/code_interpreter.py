"""
Code Interpreter API
Provides a REST interface for safely executing AI-generated code inside E2B or gVisor sandboxes.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/interpreter", tags=["Interpreter"])

class CodeExecutionRequest(BaseModel):
    code: str
    language: str = "python"
    timeout_seconds: int = 30
    network_access: bool = False

class CodeExecutionResponse(BaseModel):
    stdout: str
    stderr: str
    exit_code: int
    execution_time_ms: int

# In a real implementation, this would use the e2b SDK
class SimulatedE2BClient:
    async def execute_code(self, code: str, language: str) -> CodeExecutionResponse:
        logger.info(f"Simulating execution of {language} code...")
        
        # Simple simulation to demonstrate containment
        if "rm -rf" in code or "DROP TABLE" in code.upper():
            return CodeExecutionResponse(
                stdout="",
                stderr="Permission denied: Operation blocked by sandbox policy.",
                exit_code=1,
                execution_time_ms=150
            )
            
        return CodeExecutionResponse(
            stdout=f"Simulated execution output for {language} script.",
            stderr="",
            exit_code=0,
            execution_time_ms=45
        )

# Factory for abstract client pattern
def get_interpreter_client():
    from src.config.demo_mode import DemoConfig
    # In live mode we'd return actual E2B client
    return SimulatedE2BClient()

@router.post("/execute", response_model=CodeExecutionResponse)
async def execute_code(
    request: CodeExecutionRequest,
    client: SimulatedE2BClient = Depends(get_interpreter_client)
):
    """
    Execute arbitrary code in an isolated ephemeral environment.
    """
    logger.info(f"Received execution request for {request.language}")
    
    try:
        response = await client.execute_code(request.code, request.language)
        return response
    except Exception as e:
        logger.error(f"Execution failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Sandbox execution failed.")
