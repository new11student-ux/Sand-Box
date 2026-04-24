"""
Advanced Cybersecurity Sandbox Platform - Demo Launcher
Runs the dashboard with a mocked database for presentation.
"""

import asyncio
import json
import logging
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, AsyncMock

import uvicorn
from fastapi import FastAPI, Request

# Add project root to path
sys.path.append(".")

# ============================================================================
# Mock Data Generator
# ============================================================================

def generate_mock_samples():
    return [
        {
            "id": "abc12345-0001-4000-8000-000000000001",
            "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "file_name": "malicious_payload.exe",
            "file_size": 1024567,
            "file_type": "PE32 executable (console) Intel 80386, for MS Windows",
            "mime_type": "application/x-dosexec",
            "status": "completed",
            "verdict": "malicious",
            "confidence_score": 0.9452,
            "ml_score": 0.9821,
            "submitted_at": datetime.now(timezone.utc) - timedelta(hours=2),
            "analysis_completed_at": datetime.now(timezone.utc) - timedelta(hours=1, minutes=45),
            "priority": 5
        },
        {
            "id": "abc12345-0002-4000-8000-000000000002",
            "sha256_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            "file_name": "benign_installer.msi",
            "file_size": 5242880,
            "file_type": "Microsoft Software Installer",
            "mime_type": "application/x-msi",
            "status": "completed",
            "verdict": "benign",
            "confidence_score": 0.8821,
            "ml_score": 0.0521,
            "submitted_at": datetime.now(timezone.utc) - timedelta(hours=5),
            "analysis_completed_at": datetime.now(timezone.utc) - timedelta(hours=4, minutes=30),
            "priority": 3
        },
        {
            "id": "abc12345-0003-4000-8000-000000000003",
            "sha256_hash": "8a3952a26569f10f44391e6c466488344604d559a43a0544f808f370f1a92e62",
            "file_name": "suspicious_macro.docm",
            "file_size": 45600,
            "file_type": "Microsoft Word 2007+",
            "mime_type": "application/vnd.ms-word.document.macroEnabled.12",
            "status": "completed",
            "verdict": "suspicious",
            "confidence_score": 0.6541,
            "ml_score": 0.7214,
            "submitted_at": datetime.now(timezone.utc) - timedelta(minutes=45),
            "analysis_completed_at": datetime.now(timezone.utc) - timedelta(minutes=10),
            "priority": 8
        }
    ]

def generate_mock_ebpf_events(sample_id):
    events = []
    base_time = datetime.now(timezone.utc) - timedelta(minutes=15)
    syscalls = [
        ("openat", "file", True), ("read", "file", False), ("write", "file", False),
        ("connect", "network", True), ("execve", "process", True), ("mmap", "memory", False),
        ("ptrace", "process", True), ("setuid", "process", True)
    ]
    
    for i in range(50):
        name, cat, susp = syscalls[i % len(syscalls)]
        events.append({
            "timestamp": base_time + timedelta(milliseconds=i * 100),
            "pid": 1234,
            "tid": 1234,
            "process_name": "malicious_payload.exe" if "0001" in sample_id else "app.exe",
            "syscall_name": name,
            "category": cat,
            "suspicious": susp and ("0001" in sample_id or "0003" in sample_id)
        })
    return events

def generate_mock_falco_alerts(sample_id):
    if "0002" in sample_id: # Benign
        return [{
            "timestamp": datetime.now(timezone.utc) - timedelta(minutes=20),
            "rule": "Sandbox Analysis Started",
            "priority": "INFO",
            "output": "Analysis session started for benign_installer.msi",
            "mitre_attack_id": None
        }]
    
    return [
        {
            "timestamp": datetime.now(timezone.utc) - timedelta(minutes=14),
            "rule": "Sandbox Container Escape Attempt",
            "priority": "CRITICAL",
            "output": "Container escape attempt detected (user=root command=chroot /host)",
            "mitre_attack_id": "T1611"
        },
        {
            "timestamp": datetime.now(timezone.utc) - timedelta(minutes=12),
            "rule": "Sandbox Unauthorized Network Egress",
            "priority": "WARNING",
            "output": "Unauthorized network egress from sandbox (dest=1.2.3.4:4444)",
            "mitre_attack_id": "T1048"
        },
        {
            "timestamp": datetime.now(timezone.utc) - timedelta(minutes=10),
            "rule": "Sandbox Privilege Escalation",
            "priority": "CRITICAL",
            "output": "Privilege escalation in sandbox (user=sandbox command=setuid 0)",
            "mitre_attack_id": "T1068"
        }
    ]

# ============================================================================
# Mock DB Layer
# ============================================================================

class MockDBConnection:
    async def fetch(self, query, *args):
        if "FROM samples" in query:
            return generate_mock_samples()
        if "FROM iocs" in query:
            return [{"ioc_type": "ip", "value": "1.2.3.4", "confidence": "high", "first_seen": datetime.now()}]
        if "FROM v_active_iocs" in query:
            all_iocs = [
                {"ioc_type": "ip", "value": "1.2.3.4", "confidence": "high", "tlp": "red", "ti_tags": '["malware","c2"]', "first_seen": datetime.now(), "last_seen": datetime.now(), "sample_count": 5},
                {"ioc_type": "ip", "value": "185.220.101.33", "confidence": "high", "tlp": "amber", "ti_tags": '["tor_exit_node"]', "first_seen": datetime.now(), "last_seen": datetime.now(), "sample_count": 3},
                {"ioc_type": "domain", "value": "evil-c2-server.ru", "confidence": "high", "tlp": "red", "ti_tags": '["c2","APT28"]', "first_seen": datetime.now(), "last_seen": datetime.now(), "sample_count": 2},
                {"ioc_type": "file_hash", "value": "e3b0c44298fc1c149afbf4c8996fb924", "confidence": "high", "tlp": "white", "ti_tags": '["ransomware"]', "first_seen": datetime.now(), "last_seen": datetime.now(), "sample_count": 8},
                {"ioc_type": "url", "value": "http://malicious.com/payload.sh", "confidence": "medium", "tlp": "amber", "ti_tags": '["dropper"]', "first_seen": datetime.now(), "last_seen": datetime.now(), "sample_count": 1},
                {"ioc_type": "mutex", "value": "Global\\\\MalwareMutex_v2", "confidence": "high", "tlp": "red", "ti_tags": '["trojan"]', "first_seen": datetime.now(), "last_seen": datetime.now(), "sample_count": 4},
            ]
            if args:
                return [i for i in all_iocs if i["ioc_type"] == args[0]]
            return all_iocs
        if "FROM v_mitre_attack_coverage" in query:
            return [
                {"mitre_attack_tactic": "Persistence", "mitre_attack_technique": "T1053 Scheduled Task", "detection_count": 12, "detecting_rules": ["scheduled_task_creation", "at_command"]},
                {"mitre_attack_tactic": "Persistence", "mitre_attack_technique": "T1547 Boot/Logon Autostart", "detection_count": 7, "detecting_rules": ["registry_run_key"]},
                {"mitre_attack_tactic": "Execution", "mitre_attack_technique": "T1059.001 PowerShell", "detection_count": 15, "detecting_rules": ["powershell_encoded_command", "powershell_download"]},
                {"mitre_attack_tactic": "Execution", "mitre_attack_technique": "T1059.003 Windows Command Shell", "detection_count": 4, "detecting_rules": ["cmd_suspicious_args"]},
                {"mitre_attack_tactic": "Defense Evasion", "mitre_attack_technique": "T1055 Process Injection", "detection_count": 9, "detecting_rules": ["remote_thread_injection", "dll_injection"]},
                {"mitre_attack_tactic": "Defense Evasion", "mitre_attack_technique": "T1027 Obfuscated Files", "detection_count": 3, "detecting_rules": ["base64_encoded_payload"]},
                {"mitre_attack_tactic": "Command and Control", "mitre_attack_technique": "T1071 Application Layer Protocol", "detection_count": 6, "detecting_rules": ["http_c2_beacon"]},
                {"mitre_attack_tactic": "Exfiltration", "mitre_attack_technique": "T1048 Exfiltration Over Alternative Protocol", "detection_count": 2, "detecting_rules": ["dns_tunneling"]},
                {"mitre_attack_tactic": "Discovery", "mitre_attack_technique": "T1082 System Information Discovery", "detection_count": 1, "detecting_rules": ["systeminfo_command"]},
            ]
        if "FROM ebpf_events" in query:
            return generate_mock_ebpf_events(args[0])
        if "FROM falco_alerts" in query:
            return generate_mock_falco_alerts(args[0])
        if "FROM behaviors" in query:
            return [{"behavior_type": "network", "severity": "high", "description": "Connection to C2 server", "mitre_attack_id": "T1071"}]
        return []

    async def fetchrow(self, query, *args):
        if "FROM samples" in query:
            samples = generate_mock_samples()
            if args:
                for s in samples:
                    if s["id"] == args[0]: return s
            return {
                "pending_samples": 0, "analyzing_samples": 0, "completed_samples": 3,
                "malicious_samples": 1, "benign_samples": 1, "total_samples": 3,
                "pending": 0, "analyzing": 0, "completed": 3, "malicious": 1, "benign": 1, "suspicious": 1,
                "avg_confidence": 0.82
            }
        if "FROM submission_queue" in query:
            return {"queue_pending": 0, "queue_processing": 0}
        return None

    async def __aenter__(self): return self
    async def __aexit__(self, exc_type, exc, tb): pass

class MockPool:
    def acquire(self): return MockDBConnection()
    async def close(self): pass

# ============================================================================
# Launch Project
# ============================================================================

async def main():
    print("Launching Sandbox Platform in Demo Mode...")
    
    # Patch asyncpg.create_pool
    import asyncpg
    asyncpg.create_pool = AsyncMock(return_value=MockPool())
    
    # 1. Import apps
    from src.frontend.dashboard import app as dashboard_app
    from src.api.submission import app as submission_app
    
    # 2. Mock Security in submission app for demo
    from src.api.submission import verify_api_key
    async def mock_verify_api_key():
        return {"username": "admin", "role": "admin"}
    submission_app.dependency_overrides[verify_api_key] = mock_verify_api_key

    # 3. Combine them: Mount submission API into dashboard
    # The dashboard serves /advanced, which calls /api/v1/advanced/...
    # submission_app already has /api/v1/... prefixes
    dashboard_app.mount("/api/v1", submission_app)
    
    # 4. Launch
    config = uvicorn.Config(dashboard_app, host="127.0.0.1", port=3001, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
