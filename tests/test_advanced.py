import pytest
import asyncio
from src.advanced.schemas import CowrieEvent
from src.advanced.drakvuf_client import get_drakvuf_client, SimulatedDrakvufClient
from src.advanced.cowrie_parser import CowrieParser
from src.advanced.mitre_tagger import MitreTagger

@pytest.mark.asyncio
async def test_drakvuf_simulator_memory_artifacts():
    """Verify simulated DRAKVUF report includes realistic introspection data"""
    client = get_drakvuf_client(mode="simulated")
    
    # Submit job
    job = await client.submit_sample("hash123")
    assert job.status == "pending"
    
    # Fast-forward time manually for testing by mutating internal state
    client.jobs[job.job_id]["submitted_time"] -= 10.0
    
    report = await client.get_results(job.job_id)
    assert report.status == "completed"
    assert len(report.memory_dumps) > 0
    assert any("shellcode" in dump.get("content", "") for dump in report.memory_dumps)
    assert len(report.syscall_trace) > 0

def test_cowrie_parser_file_download():
    """Verify auto-creation of Sample from honeypot file download"""
    parser = CowrieParser()
    event = CowrieEvent(
        eventid="cowrie.session.file_download",
        src_ip="192.0.2.100",
        session="sess1",
        shasum="a"*64,
        url="http://evil.com/malware.exe"
    )
    
    result = parser.parse_event(event)
    assert result.created_sample_hash == "a"*64
    assert result.created_ioc_value == "192.0.2.100"

def test_mitre_tagger_powershell_detection():
    """Verify T1059.001 tagging for PowerShell execution chains"""
    tagger = MitreTagger()
    # Ensure rules are loaded
    assert len(tagger.rules) > 0
    
    behaviors = [
        {"syscall": "CreateProcess", "process_name": "powershell.exe", "parent_process": "winword.exe"},
        {"syscall": "WriteFile", "path": "C:\\temp\\payload.ps1"}
    ]
    
    tags = tagger.analyze(behaviors)
    technique_ids = [t.technique_id for t in tags]
    
    assert "T1059.001" in technique_ids
    tag = next(t for t in tags if t.technique_id == "T1059.001")
    assert tag.confidence == 0.85
