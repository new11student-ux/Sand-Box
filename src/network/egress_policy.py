"""
Dynamic Network Egress Policy Engine
Controls what destinations the sandboxes and AI agents can reach.
Prevents lateral movement and C2 communication.
"""

import logging
from typing import List

logger = logging.getLogger(__name__)

class EgressPolicyEngine:
    def __init__(self):
        self.whitelisted_domains = [
            "api.github.com",
            "pypi.org",
            "registry.npmjs.org",
            "archive.ubuntu.com"
        ]
        
        self.blocked_cidrs = [
            "10.0.0.0/8",      # Internal VPC
            "172.16.0.0/12",   # Internal Docker/K8s
            "192.168.0.0/16",  # Internal Network
            "169.254.169.254/32" # Cloud metadata endpoint (AWS/GCP)
        ]

    def is_destination_allowed(self, destination_ip: str, domain: str = None) -> bool:
        """
        Checks if a given network connection attempt is allowed.
        This logic would typically feed into eBPF rules or iptables.
        """
        if domain and domain in self.whitelisted_domains:
            logger.debug(f"Egress ALLOWED to whitelisted domain: {domain}")
            return True
            
        # Check against blocked internal CIDRs (simplified for demo)
        for cidr in self.blocked_cidrs:
            prefix = cidr.split('/')[0]
            # Simple prefix matching for demonstration
            if destination_ip.startswith(prefix.rsplit('.', 1)[0]):
                logger.warning(f"Egress BLOCKED to internal/metadata IP: {destination_ip}")
                return False
                
        logger.info(f"Egress ALLOWED to external IP: {destination_ip}")
        return True

    def update_blocklist(self, new_threat_ips: List[str]):
        """Dynamically update blocklist based on Threat Intel feeds."""
        for ip in new_threat_ips:
            if ip not in self.blocked_cidrs:
                self.blocked_cidrs.append(f"{ip}/32")
        logger.info(f"Egress blocklist updated with {len(new_threat_ips)} new IPs.")
