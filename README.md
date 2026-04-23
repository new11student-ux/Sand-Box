# Advanced Cybersecurity Sandbox Platform

A comprehensive, multi-layered sandbox environment for malware analysis, AI agent containment, and threat intelligence operations.

## Overview

This platform integrates best-in-class open-source security tools into a unified orchestration layer, providing:

- **Malware Analysis** - CAPEv2-based detonation with behavioral monitoring
- **AI Agent Sandboxing** - Ephemeral execution for LLM-generated code
- **Real-time Monitoring** - eBPF-powered syscall interception via Azazel/Falco
- **Threat Intelligence** - MISP integration with automated IOC enrichment
- **Remote Browser Isolation** - Kasm-based containerized browsing
- **Document Sanitization** - Dangerzone-style pixelation for safe file handling

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  SUBMISSION LAYER                       │
│         Email gateway / API / CI-CD hook                │
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

- Docker & Docker Compose
- Python 3.11+
- 16GB RAM minimum (32GB recommended)
- Nested virtualization support (for CAPEv2)

### Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd sandbox-platform
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start services**
   ```bash
   # Basic setup (API + Database)
   docker-compose up -d postgres redis api dashboard

   # Full setup (includes CAPEv2, MISP, etc.)
   docker-compose --profile full up -d
   ```

4. **Run database migrations**
   ```bash
   python src/database/migrate.py
   ```

5. **Generate API key**
   ```bash
   # Default admin user created with password: change-me-immediately
   # Change immediately in production!
   ```

## API Usage

### Submit a Sample

```bash
curl -X POST http://localhost:8000/api/v1/samples \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "file=@malware.exe" \
  -F "priority=8"
```

### Check Sample Status

```bash
curl http://localhost:8000/api/v1/samples/{sample_id} \
  -H "Authorization: Bearer YOUR_API_KEY"
```

### Get Analysis Report

```bash
curl http://localhost:8000/api/v1/samples/{sample_id}/report \
  -H "Authorization: Bearer YOUR_API_KEY"
```

### Search IOCs

```bash
curl "http://localhost:8000/api/v1/iocs?ioc_type=domain&value=evil.com" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

## Project Structure

```
sandbox-platform/
├── src/
│   ├── api/                    # REST API (FastAPI)
│   │   └── submission.py       # Sample submission endpoints
│   ├── worker/                 # Background job processor
│   │   └── main.py             # CAPEv2 orchestration
│   ├── ml/                     # Machine learning models
│   │   └── false_positive_classifier.py
│   ├── database/               # Database schema & migrations
│   │   ├── schema.sql
│   │   └── migrate.py
│   └── frontend/               # Analyst dashboard
│       ├── dashboard.py
│       └── templates/
├── docker/                     # Docker configurations
│   ├── Dockerfile.api
│   ├── Dockerfile.worker
│   └── nginx.conf
├── tests/                      # Test suite
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Components

### Phase 1: Foundation (Months 1-3)
- [x] PostgreSQL schema with samples, behaviors, IOCs tables
- [x] FastAPI submission API with authentication
- [x] Docker Compose development environment
- [ ] CAPEv2 integration
- [ ] MISP threat intelligence sync

### Phase 2: Behavioral Monitoring (Months 4-6)
- [ ] Azazel eBPF tracer integration
- [ ] Falco runtime security rules
- [ ] ML false positive classifier

### Phase 3: AI Agent Sandboxing (Months 7-9)
- [ ] E2B code interpreter
- [ ] gVisor runtime isolation
- [ ] Network egress policies

### Phase 4: Remote Browser Isolation (Months 10-12)
- [ ] Kasm Workspaces integration
- [ ] Dangerzone document sanitization

### Phase 5: Advanced Features (Months 13-15)
- [ ] DRAKVUF hypervisor introspection
- [ ] Cowrie honeypot integration
- [ ] MITRE ATT&CK automated tagging

### Phase 6: Production Hardening (Months 16-18)
- [ ] Enarx confidential computing
- [ ] Kubernetes orchestration
- [ ] Full observability stack

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
