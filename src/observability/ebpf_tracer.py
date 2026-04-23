"""
Advanced Cybersecurity Sandbox Platform
eBPF Telemetry Pipeline

Provides syscall-level visibility into sandbox execution environments.
Supports two backends:
  - Simulated: Generates realistic syscall traces for demo/testing
  - Live: Connects to Azazel eBPF tracer (future, requires Linux)

Output: NDJSON stream compatible with Elasticsearch / Splunk.
"""

import asyncio
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Any, AsyncGenerator, Callable
from collections import Counter

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TELEMETRY_OUTPUT_DIR = Path(os.getenv("EBPF_TELEMETRY_DIR", "./storage/telemetry"))


@dataclass
class SyscallEvent:
    """Single syscall event captured by eBPF probe."""
    timestamp: float
    pid: int
    tid: int
    process_name: str
    syscall_name: str
    syscall_nr: int
    args: Dict[str, Any] = field(default_factory=dict)
    return_val: int = 0
    category: str = "other"
    sample_id: Optional[str] = None
    container_id: Optional[str] = None
    suspicious: bool = False

    def to_ndjson(self) -> str:
        """Serialize to NDJSON line."""
        d = asdict(self)
        d["@timestamp"] = datetime.fromtimestamp(
            self.timestamp, tz=timezone.utc
        ).isoformat()
        return json.dumps(d, default=str)


@dataclass
class TelemetryMetrics:
    """Aggregate metrics from a syscall event stream."""
    total_events: int = 0
    unique_syscalls: int = 0
    syscall_frequency: Dict[str, int] = field(default_factory=dict)
    category_distribution: Dict[str, int] = field(default_factory=dict)
    suspicious_count: int = 0
    process_count: int = 0
    time_span_seconds: float = 0.0
    events_per_second: float = 0.0
    top_processes: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_sequences: List[Dict[str, Any]] = field(default_factory=list)


# Syscall knowledge base
SYSCALL_DB: Dict[str, Dict[str, Any]] = {
    "execve":     {"nr": 59,  "cat": "process",  "susp": False},
    "clone":      {"nr": 56,  "cat": "process",  "susp": False},
    "fork":       {"nr": 57,  "cat": "process",  "susp": False},
    "wait4":      {"nr": 61,  "cat": "process",  "susp": False},
    "exit_group": {"nr": 231, "cat": "process",  "susp": False},
    "getpid":     {"nr": 39,  "cat": "process",  "susp": False},
    "openat":     {"nr": 257, "cat": "file",     "susp": False},
    "read":       {"nr": 0,   "cat": "file",     "susp": False},
    "write":      {"nr": 1,   "cat": "file",     "susp": False},
    "close":      {"nr": 3,   "cat": "file",     "susp": False},
    "unlink":     {"nr": 87,  "cat": "file",     "susp": False},
    "rename":     {"nr": 82,  "cat": "file",     "susp": False},
    "chmod":      {"nr": 90,  "cat": "file",     "susp": False},
    "stat":       {"nr": 4,   "cat": "file",     "susp": False},
    "socket":     {"nr": 41,  "cat": "network",  "susp": False},
    "connect":    {"nr": 42,  "cat": "network",  "susp": False},
    "bind":       {"nr": 49,  "cat": "network",  "susp": False},
    "listen":     {"nr": 50,  "cat": "network",  "susp": True},
    "sendto":     {"nr": 44,  "cat": "network",  "susp": False},
    "recvfrom":   {"nr": 45,  "cat": "network",  "susp": False},
    "mmap":       {"nr": 9,   "cat": "memory",   "susp": False},
    "mprotect":   {"nr": 10,  "cat": "memory",   "susp": True},
    "brk":        {"nr": 12,  "cat": "memory",   "susp": False},
    "munmap":     {"nr": 11,  "cat": "memory",   "susp": False},
    "ptrace":     {"nr": 101, "cat": "process",  "susp": True},
    "pivot_root": {"nr": 155, "cat": "process",  "susp": True},
    "setns":      {"nr": 308, "cat": "process",  "susp": True},
    "mount":      {"nr": 165, "cat": "file",     "susp": True},
    "chroot":     {"nr": 161, "cat": "process",  "susp": True},
    "setuid":     {"nr": 105, "cat": "process",  "susp": True},
    "setgid":     {"nr": 106, "cat": "process",  "susp": True},
}

SUSPICIOUS_SEQUENCES = [
    {"name": "Process Injection",       "pattern": ["mmap", "mprotect", "clone"],       "severity": "high",     "mitre": "T1055"},
    {"name": "Container Escape",        "pattern": ["setns", "execve"],                 "severity": "critical", "mitre": "T1611"},
    {"name": "Privilege Escalation",    "pattern": ["setuid", "execve"],                "severity": "high",     "mitre": "T1068"},
    {"name": "Reverse Shell",           "pattern": ["socket", "connect", "execve"],     "severity": "critical", "mitre": "T1059"},
    {"name": "Data Exfiltration",       "pattern": ["openat", "read", "socket", "sendto"], "severity": "high", "mitre": "T1041"},
    {"name": "File Dropper",            "pattern": ["openat", "write", "chmod", "execve"], "severity": "medium","mitre": "T1204"},
]


class EBPFTracer:
    """eBPF telemetry pipeline with simulated and live modes."""

    def __init__(self, mode: str = "simulated", output_dir: Optional[Path] = None):
        self.mode = mode
        self.output_dir = output_dir or TELEMETRY_OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._events: List[SyscallEvent] = []

    def generate_trace(
        self, sample_id: str, behavior_profile: str = "malicious",
        duration_seconds: float = 10.0, event_count: int = 200,
    ) -> List[SyscallEvent]:
        """Generate a simulated syscall trace for an analysis session."""
        events = []
        base_time = time.time()
        container_id = f"sandbox-{sample_id[:8]}"
        profile = self._get_profile(behavior_profile)
        pids = profile["pids"]
        names = profile["process_names"]

        for i in range(event_count):
            t = base_time + (i / event_count) * duration_seconds
            pid_idx = random.randint(0, len(pids) - 1)
            sc = random.choices(profile["syscalls"], weights=profile["weights"], k=1)[0]
            info = SYSCALL_DB.get(sc, {"nr": 0, "cat": "other", "susp": False})

            # Inject suspicious sequences for malicious profiles
            if behavior_profile in ("malicious", "evasive") and random.random() < 0.03:
                seq = random.choice(SUSPICIOUS_SEQUENCES[:3])
                for j, sc_name in enumerate(seq["pattern"]):
                    sc_i = SYSCALL_DB.get(sc_name, {"nr": 0, "cat": "other", "susp": False})
                    events.append(SyscallEvent(
                        timestamp=t + j * 0.001, pid=pids[pid_idx],
                        tid=pids[pid_idx] + random.randint(0, 3),
                        process_name=names[pid_idx], syscall_name=sc_name,
                        syscall_nr=sc_i["nr"], category=sc_i["cat"],
                        sample_id=sample_id, container_id=container_id,
                        suspicious=sc_i["susp"],
                    ))
                continue

            events.append(SyscallEvent(
                timestamp=t, pid=pids[pid_idx],
                tid=pids[pid_idx] + random.randint(0, 3),
                process_name=names[pid_idx], syscall_name=sc,
                syscall_nr=info["nr"],
                return_val=0 if random.random() > 0.1 else -1,
                category=info["cat"], sample_id=sample_id,
                container_id=container_id, suspicious=info["susp"],
            ))

        events.sort(key=lambda e: e.timestamp)
        self._events = events
        return events

    def _get_profile(self, name: str) -> Dict:
        profiles = {
            "malicious": {
                "pids": [1234, 1235, 1300], "process_names": ["malware.exe", "cmd.exe", "powershell.exe"],
                "syscalls": ["openat","read","write","close","stat","socket","connect","sendto","recvfrom","mmap","mprotect","execve","clone","ptrace","chmod","unlink"],
                "weights":  [12,15,10,12,8,5,5,4,4,4,3,3,2,2,2,2],
            },
            "evasive": {
                "pids": [2001, 2002], "process_names": ["explorer.exe", "svchost.exe"],
                "syscalls": ["openat","read","write","close","stat","mmap","mprotect","brk","getpid","setns","socket","connect"],
                "weights":  [10,12,8,10,15,5,4,3,6,2,3,3],
            },
            "benign": {
                "pids": [5001, 5002], "process_names": ["notepad.exe", "calc.exe"],
                "syscalls": ["openat","read","write","close","stat","mmap","brk","munmap","getpid","wait4"],
                "weights":  [15,20,10,15,10,5,5,3,3,2],
            },
        }
        return profiles.get(name, profiles["benign"])

    def write_ndjson(self, events: Optional[List[SyscallEvent]] = None, filename: Optional[str] = None) -> Path:
        """Write events to NDJSON file."""
        events = events or self._events
        if not filename:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"trace_{ts}.ndjson"
        output_path = self.output_dir / filename
        with open(output_path, "w", encoding="utf-8") as f:
            for event in events:
                f.write(event.to_ndjson() + "\n")
        logger.info("Wrote %d events to %s", len(events), output_path)
        return output_path

    def compute_metrics(self, events: Optional[List[SyscallEvent]] = None) -> TelemetryMetrics:
        """Compute aggregate metrics from syscall events."""
        events = events or self._events
        if not events:
            return TelemetryMetrics()

        sc_counter = Counter(e.syscall_name for e in events)
        cat_counter = Counter(e.category for e in events)
        proc_counter = Counter(e.process_name for e in events)
        timestamps = [e.timestamp for e in events]
        span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0

        return TelemetryMetrics(
            total_events=len(events),
            unique_syscalls=len(sc_counter),
            syscall_frequency=dict(sc_counter.most_common()),
            category_distribution=dict(cat_counter),
            suspicious_count=sum(1 for e in events if e.suspicious),
            process_count=len(proc_counter),
            time_span_seconds=round(span, 3),
            events_per_second=round(len(events) / span, 2) if span > 0 else 0,
            top_processes=[{"name": n, "count": c} for n, c in proc_counter.most_common(5)],
            suspicious_sequences=self.detect_suspicious_sequences(events),
        )

    def detect_suspicious_sequences(self, events: Optional[List[SyscallEvent]] = None) -> List[Dict[str, Any]]:
        """Detect known suspicious syscall sequences."""
        events = events or self._events
        if not events:
            return []
        detected = []
        names = [e.syscall_name for e in events]
        for seq in SUSPICIOUS_SEQUENCES:
            pattern = seq["pattern"]
            for i in range(len(names) - len(pattern) + 1):
                if names[i:i + len(pattern)] == pattern:
                    detected.append({
                        "name": seq["name"], "severity": seq["severity"],
                        "mitre": seq["mitre"], "position": i,
                        "timestamp": events[i].timestamp,
                        "pid": events[i].pid, "process": events[i].process_name,
                    })
        return detected

    async def stream_events(
        self, sample_id: str, behavior_profile: str = "malicious",
        callback: Optional[Callable[[SyscallEvent], None]] = None,
    ) -> AsyncGenerator[SyscallEvent, None]:
        """Async generator yielding syscall events in real-time simulation."""
        events = self.generate_trace(sample_id, behavior_profile)
        for event in events:
            yield event
            if callback:
                callback(event)
            await asyncio.sleep(0.01)
