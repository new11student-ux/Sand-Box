"""
AI Agent Orchestrator
Manages the lifecycle of autonomous agents interacting with the sandbox.
Enforces tool denylists and sanitizes output.
"""

import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

class AIOrchestrator:
    def __init__(self):
        # Tools the AI agent is explicitly forbidden from using
        self.tool_denylist = [
            "system_shell",     # Direct host access
            "read_env_vars",    # Secret exposure
            "modify_network",   # Changing routing rules
        ]
        
    def validate_tool_call(self, tool_name: str, arguments: Dict) -> bool:
        """Ensure the agent is not calling restricted tools."""
        if tool_name in self.tool_denylist:
            logger.warning(f"BLOCKED: Agent attempted to use restricted tool '{tool_name}'")
            return False
            
        # Additional validation (e.g., checking if arguments contain host IP)
        if "127.0.0.1" in str(arguments) or "localhost" in str(arguments):
            logger.warning(f"BLOCKED: Agent attempted local loopback access via '{tool_name}'")
            return False
            
        return True

    def sanitize_agent_output(self, raw_output: str) -> str:
        """
        Sanitizes output from the AI before returning it to the user.
        Removes accidentally leaked API keys or internal infrastructure IPs.
        """
        sanitized = raw_output
        
        # Simple redaction logic
        # In a real scenario, use regex for JWTs, AWS keys, etc.
        if "sk-" in sanitized:
            logger.info("Redacted potential API key from agent output.")
            sanitized = sanitized.replace("sk-", "[REDACTED_KEY]-")
            
        return sanitized

    def execute_agent_step(self, agent_id: str, action: Dict) -> Dict:
        """Executes a single reasoning/action step for the agent."""
        tool_name = action.get("tool")
        
        if not self.validate_tool_call(tool_name, action.get("args", {})):
            return {"status": "error", "message": "Action blocked by security policy."}
            
        logger.info(f"Executing permitted tool {tool_name} for agent {agent_id}")
        
        # Simulate tool execution
        raw_result = f"Successfully executed {tool_name}"
        clean_result = self.sanitize_agent_output(raw_result)
        
        return {"status": "success", "result": clean_result}
