import pytest
import asyncio
from src.ai_sandbox.schemas import SandboxExecutionRequest
from src.ai_sandbox.e2b_manager import get_e2b_manager, SimulatedE2BManager, RealE2BManager
from src.ai_sandbox.network_policies import generate_egress_policy, get_iptables_script

@pytest.mark.asyncio
async def test_simulated_e2b_manager_success():
    manager = get_e2b_manager(mode="simulated")
    assert isinstance(manager, SimulatedE2BManager)
    
    req = SandboxExecutionRequest(
        code="print('hello')",
        language="python",
        network_access="restricted"
    )
    
    result = await manager.execute(req)
    assert result.status == "success"
    assert "Execution started" in result.stdout
    assert "Output generated" in result.stdout
    assert result.execution_id is not None
    assert result.execution_time_ms > 0

@pytest.mark.asyncio
async def test_simulated_e2b_manager_error():
    manager = get_e2b_manager(mode="simulated")
    
    req = SandboxExecutionRequest(
        code="raise ValueError('bad')",
        language="python"
    )
    
    result = await manager.execute(req)
    assert result.status == "error"
    assert "Traceback" in result.stderr
    assert result.error_message == "Simulated runtime error"

@pytest.mark.asyncio
async def test_simulated_e2b_manager_timeout():
    manager = get_e2b_manager(mode="simulated")
    
    req = SandboxExecutionRequest(
        code="while True: pass",
        language="python",
        timeout_seconds=2
    )
    
    result = await manager.execute(req)
    assert result.status == "timeout"
    assert "timed out" in result.stderr

def test_real_e2b_manager_without_sdk():
    # If SDK is not installed, it should fallback safely to error status
    manager = get_e2b_manager(mode="live", api_key="fake_key")
    assert isinstance(manager, RealE2BManager)
    
    # We test the synchronous part of the execute fallback
    import asyncio
    
    req = SandboxExecutionRequest(code="print(1)")
    result = asyncio.run(manager.execute(req))
    
    # Since we don't have the SDK installed in this env, it returns error gracefully
    assert result.status == "error"
    assert "Missing dependency" in result.error_message

def test_generate_egress_policy_restricted():
    policy = generate_egress_policy("restricted", ["api.github.com"])
    assert policy["access_level"] == "restricted"
    assert policy["default_action"] == "DROP"
    
    rules = policy["rules"]
    assert any(r.get("port") == 53 and r.get("protocol") == "udp" for r in rules)
    assert any(r.get("destination") == "10.0.0.0/8" for r in rules)
    assert any(r.get("destination") == "api.github.com" for r in rules)

def test_generate_egress_policy_none():
    policy = generate_egress_policy("none")
    assert policy["access_level"] == "none"
    assert policy["default_action"] == "DROP"
    assert len(policy["rules"]) == 1
    assert policy["rules"][0]["destination"] == "0.0.0.0/0"

def test_get_iptables_script():
    policy = generate_egress_policy("restricted", ["example.com"])
    script = get_iptables_script(policy)
    
    assert "#!/bin/bash" in script
    assert "iptables -P OUTPUT DROP" in script
    assert "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT" in script
    assert "iptables -A OUTPUT -d 10.0.0.0/8 -j DROP" in script
    assert "iptables -A OUTPUT -d example.com -p tcp -m multiport --dports 80,443 -j ACCEPT" in script
