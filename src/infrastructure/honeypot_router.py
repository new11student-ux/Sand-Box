"""
Deception & Honeypot Routing
Transparently redirects suspicious inbound traffic and lateral movement
attempts to isolated honeypots (Cowrie, Dionaea) for intelligence gathering.
"""

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class HoneypotRouter:
    def __init__(self):
        # Map common attack ports to specific honeypot backend IPs
        # In production, these map to the internal Docker/K8s service IPs
        self.port_mappings = {
            22: "10.0.100.2",   # SSH -> Cowrie
            23: "10.0.100.2",   # Telnet -> Cowrie
            445: "10.0.100.3",  # SMB -> Dionaea/Samba
            3389: "10.0.100.4", # RDP -> PyRDP
            80: "10.0.100.5",   # HTTP -> Conpot/Snare
        }
        
    def generate_iptables_rules(self) -> list[str]:
        """
        Generates the iptables PREROUTING rules required to transparently 
        hijack traffic and forward it to the honeypot network.
        """
        rules = []
        for port, destination in self.port_mappings.items():
            rule = (
                f"iptables -t nat -A PREROUTING -p tcp --dport {port} "
                f"-j DNAT --to-destination {destination}:{port}"
            )
            rules.append(rule)
            
            # Add masquerade rule so the honeypot replies correctly
            masq_rule = (
                f"iptables -t nat -A POSTROUTING -p tcp -d {destination} "
                f"--dport {port} -j MASQUERADE"
            )
            rules.append(masq_rule)
            
        return rules

    def log_interaction(self, source_ip: str, port: int, payload: str = None):
        """
        Records an interaction with the honeypot for threat intelligence.
        This would typically be called by a webhook from Cowrie/etc.
        """
        logger.warning(
            f"HONEYPOT TRIGGERED: Activity detected from {source_ip} "
            f"on port {port}."
        )
        if payload:
            logger.debug(f"Captured payload/credentials: {payload}")
            
        # In a real implementation, this inserts into the honeypot_events table
        # and triggers MISP enrichment.
        return True
