"""
Shared test fixtures for the Sandbox Platform test suite.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_db_pool():
    """Mock asyncpg connection pool."""
    pool = AsyncMock()
    conn = AsyncMock()
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
    return pool, conn


@pytest.fixture
def mock_http_client():
    """Mock httpx.AsyncClient."""
    client = AsyncMock()
    return client


@pytest.fixture
def sample_capev2_report():
    """Sample CAPEv2 analysis report for testing."""
    return {
        "info": {"score": 7, "id": 1},
        "signatures": [
            {"name": "creates_exe", "description": "Creates executable files", "severity": 2},
            {"name": "antivm_vbox", "description": "Detects VirtualBox", "severity": 3},
        ],
        "behavior": {
            "processes": [
                {
                    "process_name": "malware.exe",
                    "pid": 1234,
                    "calls": [
                        {"api": "VirtualAllocEx", "arguments": {}},
                        {"api": "WriteProcessMemory", "arguments": {}},
                        {"api": "CreateRemoteThread", "arguments": {}},
                        {"api": "RegSetValueExA", "arguments": {}},
                        {"api": "IsDebuggerPresent", "arguments": {}},
                    ],
                }
            ],
            "processtree": {"name": "malware.exe", "children": [{"name": "cmd.exe", "children": []}]},
            "regkey_written": [
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware",
            ],
            "regkey_opened": [],
            "file_written": ["C:\\Users\\test\\AppData\\Local\\Temp\\payload.exe"],
            "file_read": [],
        },
        "network": {
            "domains": [{"domain": "evil-c2.example.com"}],
            "hosts": ["192.168.1.100", "10.0.0.5"],
            "tcp": [
                {"dst": "10.0.0.5", "dport": 4444, "time": 1000},
                {"dst": "10.0.0.5", "dport": 4444, "time": 1060},
                {"dst": "10.0.0.5", "dport": 4444, "time": 1120},
            ],
            "udp": [],
            "dns": [
                {"request": "evil-c2.example.com"},
                {"request": "xkjd83jfk2nsd9fj3ksd.com"},
            ],
        },
    }


@pytest.fixture
def sample_behavior_data():
    """Flat behavior data for Sigma engine testing."""
    return {
        "api_calls": [
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "RegSetValueExA", "IsDebuggerPresent",
        ],
        "registry_operations": [
            {"path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware", "type": "write"},
        ],
        "file_operations": [
            {"path": "C:\\Users\\test\\AppData\\Local\\Temp\\payload.exe", "type": "write"},
        ],
        "network": {
            "connections": [
                {"host": "10.0.0.5", "port": 4444, "timestamp": 1000},
                {"host": "10.0.0.5", "port": 4444, "timestamp": 1060},
                {"host": "10.0.0.5", "port": 4444, "timestamp": 1120},
            ],
            "dns": [
                {"query": "evil-c2.example.com"},
                {"query": "xkjd83jfk2nsd9fj3ksd.com"},
            ],
        },
        "process_tree": {"name": "malware.exe", "children": [{"name": "cmd.exe", "children": []}]},
    }


@pytest.fixture
def benign_behavior_data():
    """Benign behavior data that should NOT trigger Sigma rules."""
    return {
        "api_calls": ["CreateFileW", "ReadFile", "CloseHandle", "GetSystemInfo"],
        "registry_operations": [
            {"path": "HKCU\\Software\\MyApp\\Settings", "type": "read"},
        ],
        "file_operations": [
            {"path": "C:\\Users\\test\\Documents\\report.docx", "type": "read"},
        ],
        "network": {
            "connections": [
                {"host": "api.github.com", "port": 443, "timestamp": 1000},
            ],
            "dns": [
                {"query": "api.github.com"},
            ],
        },
        "process_tree": {"name": "notepad.exe", "children": []},
    }
