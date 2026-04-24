# Advanced Cybersecurity Sandbox Platform

A comprehensive, multi-layered sandbox environment for malware analysis, AI agent containment, and threat intelligence operations. This platform transitions from an academic prototype to a production-ready system with integrated isolation, machine learning, and deception capabilities.

## Overview

This platform integrates best-in-class open-source security tools into a unified orchestration layer, providing:

- **Malware Analysis** - CAPEv2-based detonation with behavioral monitoring
- **AI Agent Sandboxing** - Ephemeral execution for LLM-generated code via E2B/gVisor
- **Real-time Monitoring** - eBPF-powered syscall interception via Azazel/Falco
- **Threat Intelligence** - MISP integration with automated IOC enrichment
- **Remote Browser Isolation** - Kasm-based containerized browsing
- **Document Sanitization** - Dangerzone-style pixelation for safe file handling
- **Advanced Deception** - Cowrie honeypot routing for attacker behavior analysis

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  SUBMISSION LAYER                       │
│         Email gateway / API / Dashboard                 │
└───────────────────┬─────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│              PRE-ANALYSIS ENRICHMENT                    │
│     MISP TI Lookup → YARA pre-scan → Priority Score     │
└───────────────────┬─────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│            SANDBOX ORCHESTRATION LAYER                  │
│  CAPEv2 / E2B / Kasm (profile-selected)                 │
└───────────────────┬─────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│             BEHAVIORAL ANALYSIS ENGINE                  │
│   eBPF/ETW telemetry → ML scoring → Sigma rules         │
└───────────────────┬─────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────────────┐
│              OUTPUT & FEEDBACK LAYER                    │
│  IOC extraction → MISP push → SIEM alert → Analyst UI   │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- **Docker Desktop** (Recommended) or Linux with Docker Engine
- **Python 3.11+**
- **16GB RAM minimum** (32GB recommended for full CAPEv2 stack)

### Deployment (Docker Compose)

1. **Clone the repository**
   ```bash
   git clone https://github.com/new11student-ux/Sand-Box.git
   cd sandbox-platform
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your security keys and configuration
   ```

3. **Launch the platform**
   ```bash
   # Start core services (API + Dashboard + PostgreSQL)
   docker-compose -f docker-compose.dev.yml up --build -d
   ```

The platform will be available at:
- **Dashboard**: [http://localhost:8000](http://localhost:8000)
- **API Docs**: [http://localhost:8000/api/v1/docs](http://localhost:8000/api/v1/docs)

## Built-in AI Capabilities

The platform features an advanced **AI Agent Sandbox** designed for safely executing and governing untrusted AI-generated code:

- **Isolation**: Code executes in ephemeral gVisor-hardened containers.
- **Governance**: The `orchestrator.py` enforces egress policies and tool denylists.
- **Explainability**: ML-based verdicts include SHAP explanations for academic transparency.
- **Playbooks**: Automated Incident Response (IR) playbook generation based on analysis reports.

## Project Structure

```
sandbox-platform/
├── Dockerfile                    # Unified production container
├── docker-compose.dev.yml        # Minimal deployment stack
├── src/
│   ├── main.py                   # Integrated server launcher
│   ├── api/                      # REST API implementation
│   ├── frontend/                 # Analyst dashboard & templates
│   ├── ai_sandbox/               # AI agent containment logic
│   ├── ml/                       # XGBoost malware classifier
│   ├── worker/                   # Background detonation worker
│   ├── database/                 # SQL schema & migrations
│   └── infrastructure/           # K8s, Honeypots, & Retention
├── docs/                         # Detailed design & documentation
├── tests/                        # Security & validation suite
└── .env.example                  # Configuration template
```

## Implementation Status (Phases 0-6 Complete)

### Phase 1: Foundation
- [x] PostgreSQL schema with encrypted samples & audit logs
- [x] FastAPI submission API with RBAC
- [x] Unified Docker deployment strategy
- [x] CAPEv2 & MISP baseline integration

### Phase 2: Behavioral Monitoring
- [x] eBPF-powered syscall interception
- [x] Falco runtime security alerting
- [x] XGBoost-based false positive classifier with SHAP

### Phase 3: AI Agent Sandboxing
- [x] E2B ephemeral sandbox integration
- [x] gVisor runtime hardening
- [x] Dynamic network egress filtering

### Phase 4: Isolation & Sanitization
- [x] Remote Browser Isolation (RBI) via Kasm
- [x] Dangerzone document sanitization engine

### Phase 5: Advanced Features
- [x] DRAKVUF hypervisor introspection
- [x] Cowrie/Dionaea honeypot integration
- [x] Automated MITRE ATT&CK technique mapping

### Phase 6: Production Hardening
- [x] Enarx Confidential Computing support
- [x] Kubernetes Kustomize templates for AWS
- [x] Full observability stack (Prometheus/Grafana)

## Documentation

For detailed usage, deployment, and academic context:
- 📑 **[Deployment & Usage Guide](docs/REAL_LIFE_TESTING.md)**
- 🛡️ **[Threat Model (STRIDE)](docs/THREAT_MODEL.md)**
- 🧬 **[Reproducibility Guide](docs/REPRODUCIBILITY.md)**

## Security Considerations

⚠️ **WARNING**: This platform detonates real malware. Deploy only in isolated networks.

- Use dedicated hardware for hypervisor introspection (DRAKVUF).
- Ensure network segmentation between management and sandbox planes.
- Rotate API keys and database credentials frequently.

## License

AGPL-3.0 - See [LICENSE](LICENSE) file for details.

## Acknowledgments

This project integrates many excellent open-source security tools:
- [CAPEv2](https://github.com/kevoreilly/CAPEv2) | [MISP](https://github.com/MISP/MISP) | [Sigma HQ](https://github.com/SigmaHQ/sigma) | [Falco](https://github.com/falcosecurity/falco) | [E2B](https://github.com/e2b-dev/E2B) | [gVisor](https://github.com/google/gvisor)
nths 13-15)
- [x] DRAKVUF hypervisor introspection
- [x] Cowrie honeypot integration
- [x] MITRE ATT&CK automated tagging

### Phase 6: Production Hardening (Months 16-18)
- [x] Enarx confidential computing
- [x] Kubernetes orchestration
- [x] Full observability stack

## Security Considerations

⚠️ **WARNING**: This platform is designed to handle malicious software. Deploy only in isolated, controlled environments.

- Never expose sandbox interfaces directly to the internet
- Use network segmentation to isolate sandbox VMs
- Enable encryption for sample storage
- Regularly update all components
- Monitor for sandbox escape attempts

## Dataset Sources

For training the ML classifier:
- [EMBER Dataset](https://github.com/elastic/ember)
- [MalwareBazaar](https://bazaar.abuse.ch/)
- [VirusShare](https://virusshare.com/)
- [theZoo](https://github.com/ytisf/theZoo)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `pytest tests/`
4. Submit a pull request

## License

AGPL-3.0 - See LICENSE file for details

## Acknowledgments

This project integrates many excellent open-source security tools:
- [CAPEv2](https://github.com/kevoreilly/CAPEv2)
- [MISP](https://github.com/MISP/MISP)
- [Sigma HQ](https://github.com/SigmaHQ/sigma)
- [Falco](https://github.com/falcosecurity/falco)
- [E2B](https://github.com/e2b-dev/E2B)
- [gVisor](https://github.com/google/gvisor)
