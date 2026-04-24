"""
AI Agent Sandboxing Module
Handles ephemeral, isolated execution environments for LLM-generated code.
"""

from .schemas import SandboxExecutionRequest, SandboxExecutionResult
from .e2b_manager import E2BManager, SimulatedE2BManager, get_e2b_manager
from .network_policies import generate_egress_policy

__all__ = [
    "SandboxExecutionRequest",
    "SandboxExecutionResult",
    "E2BManager",
    "SimulatedE2BManager",
    "get_e2b_manager",
    "generate_egress_policy"
]
