"""
Tests for the eBPF Telemetry Pipeline.
"""

import json
import pytest
import tempfile
from pathlib import Path
from src.observability.ebpf_tracer import (
    EBPFTracer, SyscallEvent, TelemetryMetrics,
    SYSCALL_DB, SUSPICIOUS_SEQUENCES,
)


class TestSyscallEvent:
    """Test SyscallEvent data model."""

    def test_create_event(self):
        event = SyscallEvent(
            timestamp=1000.0, pid=1234, tid=1234,
            process_name="test.exe", syscall_name="openat",
            syscall_nr=257, category="file",
        )
        assert event.pid == 1234
        assert event.syscall_name == "openat"
        assert event.suspicious is False

    def test_to_ndjson(self):
        event = SyscallEvent(
            timestamp=1000.0, pid=1234, tid=1234,
            process_name="test.exe", syscall_name="openat",
            syscall_nr=257, category="file",
            sample_id="sample-123",
        )
        line = event.to_ndjson()
        data = json.loads(line)
        assert data["pid"] == 1234
        assert data["syscall_name"] == "openat"
        assert data["sample_id"] == "sample-123"
        assert "@timestamp" in data

    def test_suspicious_flag(self):
        event = SyscallEvent(
            timestamp=1000.0, pid=1, tid=1,
            process_name="evil", syscall_name="ptrace",
            syscall_nr=101, suspicious=True,
        )
        assert event.suspicious is True


class TestSyscallDB:
    """Test the syscall knowledge base."""

    def test_has_common_syscalls(self):
        assert "openat" in SYSCALL_DB
        assert "execve" in SYSCALL_DB
        assert "connect" in SYSCALL_DB
        assert "mmap" in SYSCALL_DB

    def test_suspicious_syscalls_flagged(self):
        assert SYSCALL_DB["ptrace"]["susp"] is True
        assert SYSCALL_DB["setns"]["susp"] is True
        assert SYSCALL_DB["chroot"]["susp"] is True

    def test_benign_syscalls_not_flagged(self):
        assert SYSCALL_DB["read"]["susp"] is False
        assert SYSCALL_DB["write"]["susp"] is False
        assert SYSCALL_DB["openat"]["susp"] is False

    def test_categories(self):
        assert SYSCALL_DB["openat"]["cat"] == "file"
        assert SYSCALL_DB["connect"]["cat"] == "network"
        assert SYSCALL_DB["execve"]["cat"] == "process"
        assert SYSCALL_DB["mmap"]["cat"] == "memory"


class TestEBPFTracer:
    """Test eBPF tracer functionality."""

    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.tracer = EBPFTracer(mode="simulated", output_dir=self.tmpdir)

    def test_generate_malicious_trace(self):
        events = self.tracer.generate_trace(
            sample_id="test-sample-001",
            behavior_profile="malicious",
            event_count=100,
        )
        assert len(events) > 0
        assert all(isinstance(e, SyscallEvent) for e in events)
        # Malicious should have some suspicious events
        assert any(e.suspicious for e in events)
        # All events correlated to sample
        assert all(e.sample_id == "test-sample-001" for e in events)

    def test_generate_benign_trace(self):
        events = self.tracer.generate_trace(
            sample_id="test-benign",
            behavior_profile="benign",
            event_count=50,
        )
        assert len(events) > 0
        # Benign profile has no inherently suspicious syscalls
        benign_syscalls = {"openat", "read", "write", "close", "stat", "mmap", "brk", "munmap", "getpid", "wait4"}
        for e in events:
            assert e.syscall_name in benign_syscalls

    def test_generate_evasive_trace(self):
        events = self.tracer.generate_trace(
            sample_id="test-evasive",
            behavior_profile="evasive",
            event_count=100,
        )
        assert len(events) > 0
        process_names = {e.process_name for e in events}
        # Evasive uses legitimate-looking process names
        assert "explorer.exe" in process_names or "svchost.exe" in process_names

    def test_events_sorted_by_timestamp(self):
        events = self.tracer.generate_trace("sort-test", event_count=50)
        timestamps = [e.timestamp for e in events]
        assert timestamps == sorted(timestamps)

    def test_container_id_format(self):
        events = self.tracer.generate_trace("abc12345-def")
        assert events[0].container_id == "sandbox-abc12345"


class TestNDJSONOutput:
    """Test NDJSON file output."""

    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.tracer = EBPFTracer(mode="simulated", output_dir=self.tmpdir)

    def test_write_ndjson_creates_file(self):
        events = self.tracer.generate_trace("write-test", event_count=20)
        path = self.tracer.write_ndjson(events, filename="test.ndjson")
        assert path.exists()
        assert path.name == "test.ndjson"

    def test_ndjson_line_count(self):
        events = self.tracer.generate_trace("count-test", event_count=30)
        path = self.tracer.write_ndjson(events, filename="count.ndjson")
        with open(path) as f:
            lines = f.readlines()
        assert len(lines) == len(events)

    def test_ndjson_valid_json(self):
        events = self.tracer.generate_trace("json-test", event_count=10)
        path = self.tracer.write_ndjson(events, filename="valid.ndjson")
        with open(path) as f:
            for line in f:
                data = json.loads(line)
                assert "syscall_name" in data
                assert "@timestamp" in data


class TestMetrics:
    """Test telemetry metric computation."""

    def setup_method(self):
        self.tracer = EBPFTracer(mode="simulated", output_dir=Path(tempfile.mkdtemp()))

    def test_compute_metrics(self):
        events = self.tracer.generate_trace("metrics-test", event_count=100)
        metrics = self.tracer.compute_metrics(events)

        assert isinstance(metrics, TelemetryMetrics)
        assert metrics.total_events == len(events)
        assert metrics.unique_syscalls > 0
        assert metrics.process_count > 0
        assert len(metrics.syscall_frequency) > 0
        assert len(metrics.category_distribution) > 0

    def test_empty_metrics(self):
        metrics = self.tracer.compute_metrics([])
        assert metrics.total_events == 0
        assert metrics.unique_syscalls == 0

    def test_suspicious_count(self):
        events = self.tracer.generate_trace("susp-test", behavior_profile="malicious", event_count=200)
        metrics = self.tracer.compute_metrics(events)
        assert metrics.suspicious_count >= 0

    def test_top_processes(self):
        events = self.tracer.generate_trace("proc-test", event_count=100)
        metrics = self.tracer.compute_metrics(events)
        assert len(metrics.top_processes) > 0
        assert "name" in metrics.top_processes[0]
        assert "count" in metrics.top_processes[0]


class TestSuspiciousSequenceDetection:
    """Test suspicious syscall sequence detection."""

    def test_detect_known_sequence(self):
        """Manually construct a sequence that matches a pattern."""
        tracer = EBPFTracer(mode="simulated", output_dir=Path(tempfile.mkdtemp()))
        # Create events matching "Container Escape" pattern: setns, execve
        events = [
            SyscallEvent(timestamp=1.0, pid=1, tid=1, process_name="evil",
                         syscall_name="setns", syscall_nr=308),
            SyscallEvent(timestamp=1.001, pid=1, tid=1, process_name="evil",
                         syscall_name="execve", syscall_nr=59),
        ]
        detected = tracer.detect_suspicious_sequences(events)
        assert len(detected) > 0
        assert detected[0]["name"] == "Container Escape"
        assert detected[0]["mitre"] == "T1611"

    def test_no_false_positive_on_benign(self):
        """Benign syscall stream shouldn't trigger dangerous sequences."""
        tracer = EBPFTracer(mode="simulated", output_dir=Path(tempfile.mkdtemp()))
        events = [
            SyscallEvent(timestamp=i, pid=1, tid=1, process_name="notepad",
                         syscall_name=sc, syscall_nr=0)
            for i, sc in enumerate(["openat", "read", "write", "close", "read", "write"])
        ]
        detected = tracer.detect_suspicious_sequences(events)
        assert len(detected) == 0

    def test_suspicious_sequences_db(self):
        """Verify all defined sequences have required fields."""
        for seq in SUSPICIOUS_SEQUENCES:
            assert "name" in seq
            assert "pattern" in seq
            assert "severity" in seq
            assert "mitre" in seq
            assert len(seq["pattern"]) >= 2
