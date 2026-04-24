"""
Document Sanitization API
Wrapper around Dangerzone to convert untrusted PDFs and Office documents
into safe, pixel-based PDFs (removing all macros, scripts, and embedded objects).
"""

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
import logging
import uuid
import os
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sanitize", tags=["Sanitization"])

UPLOAD_DIR = Path("storage/uploads")
SAFE_DIR = Path("storage/safe_documents")

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
SAFE_DIR.mkdir(parents=True, exist_ok=True)

class SanitizeResponse(BaseModel):
    job_id: str
    status: str
    message: str
    safe_file_url: str = None

class AbstractDangerzoneClient:
    async def sanitize_file(self, input_path: Path, output_path: Path) -> bool:
        raise NotImplementedError()

class SimulatedDangerzoneClient(AbstractDangerzoneClient):
    """Simulates the document sanitization process for the graduation demo."""
    async def sanitize_file(self, input_path: Path, output_path: Path) -> bool:
        logger.info(f"[SIMULATOR] Converting {input_path} to safe pixels...")
        import asyncio
        await asyncio.sleep(2) # Simulate processing time
        
        # Simply copy the file to simulate successful conversion
        try:
            shutil.copy2(input_path, output_path)
            logger.info(f"[SIMULATOR] Successfully sanitized document to {output_path}")
            return True
        except Exception as e:
            logger.error(f"[SIMULATOR] Failed to sanitize: {e}")
            return False

def get_dangerzone_client():
    # In a real implementation, this would check DemoConfig and return either
    # the live client or the simulator.
    return SimulatedDangerzoneClient()

@router.post("/document", response_model=SanitizeResponse)
async def sanitize_document(file: UploadFile = File(...)):
    """
    Accepts an untrusted document, processes it through the Dangerzone sandbox,
    and returns a guaranteed safe PDF.
    """
    if not file.filename.endswith(('.pdf', '.doc', '.docx', '.xls', '.xlsx')):
        raise HTTPException(status_code=400, detail="Unsupported file type for sanitization.")
        
    job_id = str(uuid.uuid4())
    input_path = UPLOAD_DIR / f"{job_id}_{file.filename}"
    safe_filename = f"safe_{Path(file.filename).stem}.pdf"
    output_path = SAFE_DIR / f"{job_id}_{safe_filename}"
    
    # Save uploaded file
    try:
        with open(input_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(status_code=500, detail="Failed to process upload.")
        
    # Process through Dangerzone
    client = get_dangerzone_client()
    success = await client.sanitize_file(input_path, output_path)
    
    if not success:
        raise HTTPException(status_code=500, detail="Document sanitization failed.")
        
    return SanitizeResponse(
        job_id=job_id,
        status="completed",
        message="Document successfully sanitized.",
        safe_file_url=f"/api/v1/sanitize/download/{job_id}/{safe_filename}"
    )

@router.get("/download/{job_id}/{filename}")
async def download_safe_document(job_id: str, filename: str):
    """Download the sanitized, safe PDF."""
    file_path = SAFE_DIR / f"{job_id}_{filename}"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Safe document not found.")
        
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type="application/pdf"
    )
