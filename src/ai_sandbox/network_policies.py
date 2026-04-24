import json
from typing import List, Dict

def generate_egress_policy(access_level: str, allowed_domains: List[str] = None) -> Dict[str, any]:
    """
    Generates network egress policies for isolated containers (e.g. gVisor or Docker).
    This outputs configuration rules that can be applied to iptables or Docker network configurations.
    """
    if not allowed_domains:
        allowed_domains = []
        
    policy = {
        "access_level": access_level,
        "default_action": "DROP",
        "rules": []
    }
    
    if access_level == "none":
        policy["rules"].append({"type": "egress", "action": "DROP", "destination": "0.0.0.0/0"})
        
    elif access_level == "restricted":
        # Allow DNS resolution
        policy["rules"].append({"type": "egress", "action": "ACCEPT", "protocol": "udp", "port": 53})
        policy["rules"].append({"type": "egress", "action": "ACCEPT", "protocol": "tcp", "port": 53})
        
        # Deny internal RFC1918 traffic
        policy["rules"].append({"type": "egress", "action": "DROP", "destination": "10.0.0.0/8"})
        policy["rules"].append({"type": "egress", "action": "DROP", "destination": "172.16.0.0/12"})
        policy["rules"].append({"type": "egress", "action": "DROP", "destination": "192.168.0.0/16"})
        
        # Allow specific domains
        for domain in allowed_domains:
            policy["rules"].append({
                "type": "egress", 
                "action": "ACCEPT", 
                "destination": domain,
                "protocol": "tcp",
                "ports": [80, 443]
            })
            
        # Deny everything else
        policy["rules"].append({"type": "egress", "action": "DROP", "destination": "0.0.0.0/0"})
        
    elif access_level == "full":
        policy["default_action"] = "ACCEPT"
        policy["rules"].append({"type": "egress", "action": "ACCEPT", "destination": "0.0.0.0/0"})
        
    return policy

def get_iptables_script(policy: Dict[str, any]) -> str:
    """Converts a policy dict into a bash script containing iptables rules."""
    lines = ["#!/bin/bash", "# Auto-generated Egress Policy", "iptables -F OUTPUT"]
    
    if policy["access_level"] == "none":
        lines.append("iptables -P OUTPUT DROP")
        return "\n".join(lines)
        
    if policy["access_level"] == "full":
        lines.append("iptables -P OUTPUT ACCEPT")
        return "\n".join(lines)
        
    # Restricted
    lines.append("iptables -P OUTPUT DROP")
    
    for rule in policy["rules"]:
        if rule["action"] == "ACCEPT":
            if rule.get("port"):
                lines.append(f"iptables -A OUTPUT -p {rule.get('protocol', 'tcp')} --dport {rule['port']} -j ACCEPT")
            elif rule.get("destination") and not rule["destination"].startswith("0.0.0.0"):
                # Simplification: Requires domain resolution before applying iptables, 
                # or using an advanced firewall like UFW/Firewalld.
                # Just mock standard format here.
                dest = rule["destination"]
                lines.append(f"iptables -A OUTPUT -d {dest} -p tcp -m multiport --dports 80,443 -j ACCEPT")
        elif rule["action"] == "DROP":
            dest = rule.get("destination")
            if dest and not dest.startswith("0.0.0.0"):
                lines.append(f"iptables -A OUTPUT -d {dest} -j DROP")
                
    return "\n".join(lines)
