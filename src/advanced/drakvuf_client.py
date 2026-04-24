import uuid
import time
import logging
from typing import Optional
from .schemas import DrakvufAnalysisJob, DrakvufIntrospectionReport

logger = logging.getLogger(__name__)

class DrakvufClient:
    """Interface for submitting samples to a Xen-based DRAKVUF instance."""
    async def submit_sample(self, sample_hash: str) -> DrakvufAnalysisJob:
        raise NotImplementedError
        
    async def get_results(self, job_id: str) -> DrakvufIntrospectionReport:
        raise NotImplementedError

class RealDrakvufClient(DrakvufClient):
    """Implementation using a real DRAKVUF API."""
    def __init__(self, api_url: str, api_key: str):
        self.api_url = api_url
        self.api_key = api_key

    async def submit_sample(self, sample_hash: str) -> DrakvufAnalysisJob:
        logger.warning("RealDrakvufClient not fully implemented.")
        return DrakvufAnalysisJob(
            job_id=str(uuid.uuid4()),
            sample_id=sample_hash,
            status="failed"
        )

    async def get_results(self, job_id: str) -> DrakvufIntrospectionReport:
        return DrakvufIntrospectionReport(
            job_id=job_id,
            status="failed"
        )

class SimulatedDrakvufClient(DrakvufClient):
    """Simulated DRAKVUF Client for local development, featuring realistic introspection artifacts."""
    def __init__(self):
        # We store simulated job states in-memory for testing the polling mechanism
        self.jobs = {}

    async def submit_sample(self, sample_hash: str) -> DrakvufAnalysisJob:
        job_id = f"drakvuf-sim-{uuid.uuid4().hex[:8]}"
        job = DrakvufAnalysisJob(
            job_id=job_id,
            sample_id=sample_hash,
            status="pending"
        )
        self.jobs[job_id] = {
            "job": job,
            "submitted_time": time.time()
        }
        return job

    async def get_results(self, job_id: str) -> DrakvufIntrospectionReport:
        job_record = self.jobs.get(job_id)
        if not job_record:
            return DrakvufIntrospectionReport(job_id=job_id, status="failed")

        elapsed = time.time() - job_record["submitted_time"]
        
        # Simulate processing delay: pending -> running -> completed
        if elapsed < 2.0:
            return DrakvufIntrospectionReport(job_id=job_id, status="pending")
        elif elapsed < 5.0:
            return DrakvufIntrospectionReport(job_id=job_id, status="running")
        
        # After 5 seconds, it's completed. Generate realistic artifacts.
        return DrakvufIntrospectionReport(
            job_id=job_id,
            status="completed",
            memory_dumps=[
                {"address": "0x7fff5fbff000", "size": 4096, "content": "shellcode_payload \x90\x90\x90\x90", "protection": "PAGE_EXECUTE_READWRITE"},
                {"address": "0x400000", "size": 10240, "content": "PE Header ... MZ\x90\x00\x03\x00\x00\x00", "protection": "PAGE_READONLY"}
            ],
            syscall_trace=[
                {"call": "NtAllocateVirtualMemory", "args": {"RegionSize": 4096}, "suspicious": True},
                {"call": "NtWriteVirtualMemory", "args": {"ProcessHandle": "svchost.exe"}, "suspicious": True},
                {"call": "NtCreateThreadEx", "args": {"StartRoutine": "0x7fff5fbff000"}, "suspicious": True}
            ],
            injected_processes=["explorer.exe", "svchost.exe"]
        )

# Global simulator instance to preserve state across API calls in demo mode
_simulated_client = SimulatedDrakvufClient()

def get_drakvuf_client(mode: str = "simulated", api_url: Optional[str] = None, api_key: Optional[str] = None) -> DrakvufClient:
    """Factory function to get the appropriate DRAKVUF Client."""
    if mode == "live" and api_url and api_key:
        return RealDrakvufClient(api_url, api_key)
    return _simulated_client
