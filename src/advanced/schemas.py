from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

# DRAKVUF Schemas
class DrakvufAnalysisJob(BaseModel):
    job_id: str
    sample_id: str
    status: str = Field("pending", description="pending, running, completed, failed")
    created_at: datetime = Field(default_factory=datetime.utcnow)

class DrakvufIntrospectionReport(BaseModel):
    job_id: str
    status: str
    memory_dumps: List[Dict[str, Any]] = Field(default_factory=list)
    syscall_trace: List[Dict[str, Any]] = Field(default_factory=list)
    injected_processes: List[str] = Field(default_factory=list)

# Cowrie Schemas
class CowrieEvent(BaseModel):
    eventid: str
    src_ip: str
    session: str
    timestamp: Optional[str] = None
    message: Optional[str] = None
    # Flexible fields for various event types (login, command, download)
    username: Optional[str] = None
    password: Optional[str] = None
    input: Optional[str] = None
    url: Optional[str] = None
    shasum: Optional[str] = None
    outfile: Optional[str] = None

class ParsedHoneypotEvent(BaseModel):
    attacker_ip: str
    event_type: str
    raw_event: Dict[str, Any]
    created_sample_hash: Optional[str] = None
    created_ioc_value: Optional[str] = None

# MITRE Tagging Schemas
class MitreTagResult(BaseModel):
    technique_id: str
    technique_name: str
    confidence: float
    matched_conditions: List[str]
    evidence: Dict[str, Any]
    analyst_notes: Optional[str] = None
