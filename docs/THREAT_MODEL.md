# Threat Model: Advanced Sandbox Platform

## Methodology: STRIDE

This document outlines the threat model for the Advanced Cybersecurity Sandbox Platform, utilizing the STRIDE methodology to identify and mitigate potential risks associated with processing live malware and untrusted AI code.

## 1. Assets
*   **Malware Samples**: Highly sensitive executables, scripts, and documents; must remain confidential and contained.
*   **Analysis Results**: PCAPs, memory dumps, and logs that may contain exploit code, C2 infrastructure details, or sensitive strings.
*   **API Keys & Credentials**: Secrets used to interact with external services (MISP, VirusTotal, AWS).
*   **Analyst Sessions**: Authentication tokens and session data for platform access.

## 2. Threat Actors
*   **Malware Authors**: Attempting to evade detection, detect the sandbox environment, or escape containment.
*   **Compromised Analyst Accounts**: Insider threats or external attackers using stolen credentials to access sensitive intelligence.
*   **Network Adversaries**: Attackers attempting MITM, replay attacks, or exploiting open ports on the sandbox infrastructure.

## 3. STRIDE Analysis & Mitigations

| Threat Category | Specific Threat | Impact | Mitigation Strategy | Phase Implemented |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Compromised Analyst Account | High | Require short-lived JWTs. Future integration with Keycloak for MFA and strict OIDC policies. | Phase 0 |
| **Spoofing** | Threat Intel Feed Spoofing | Medium | Validate TLS certificates for MISP/TIP integrations. Use signed TI feeds. | Phase 1 |
| **Tampering** | Malware evading/altering logs | High | Use out-of-band kernel telemetry (eBPF) and hypervisor introspection (DRAKVUF) that malware cannot tamper with. | Phase 2, 5 |
| **Tampering** | Database Modification | High | Strict RBAC on PostgreSQL. Use service accounts with limited privileges. | Phase 0 |
| **Repudiation** | Analyst denies deleting sample | Medium | Comprehensive audit logging for all CRUD operations, stored immutably. | Phase 0 |
| **Information Disclosure** | Data Exfiltration by Sandbox | Critical | Network egress policy blocking all outbound traffic except strictly whitelisted APIs. gVisor network isolation. | Phase 3, 4 |
| **Information Disclosure** | Database Breach | High | PostgreSQL Transparent Data Encryption (TDE) via `pgcrypto`. Secrets managed externally. | Phase 0 |
| **Denial of Service** | Resource Exhaustion (Fork Bomb) | Medium | Container resource quotas (cgroups), timeout limits on sandbox execution (e.g., 5 mins max). | Phase 3 |
| **Denial of Service** | API Flooding | Low | Rate limiting on API endpoints using FastAPI middleware. | Phase 1 |
| **Elevation of Privilege** | Sandbox Escape (Container) | Critical | Multi-layer isolation: KVM (Hypervisor) -> gVisor (Container) -> Seccomp-bpf (Userspace). | Phase 3, 4 |
| **Elevation of Privilege** | Sandbox Escape (Host) | Critical | Falco runtime security monitoring for anomalous syscalls on the host. | Phase 2 |

## 4. Verification
The mitigations outlined above will be verified automatically via the `scripts/verify-isolation.sh` tool before any live detonation capabilities are enabled.
