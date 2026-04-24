# Advanced Cybersecurity Sandbox Platform — Deployment & Usage Guide

This document explains how to deploy the platform for real use and how to interact with every feature.

---

## Prerequisites

You need **one** of:
- **Docker Desktop** (recommended) — handles PostgreSQL, Redis, and the platform in containers.
- **Local Python 3.11+** and a running **PostgreSQL 15** instance.

---

## 1. Deployment

### Option A: Docker Compose (Recommended)

This starts PostgreSQL and the platform together. The database schema is automatically applied on first run.

```bash
cd sandbox-platform

# Copy and edit the environment file
cp .env.example .env
# Edit .env to set your own ENCRYPTION_KEY and JWT_SECRET_KEY

# Start everything
docker compose -f docker-compose.dev.yml up --build
```

Once you see `Uvicorn running on http://0.0.0.0:8000`, the platform is live:
- **Dashboard**: http://localhost:8000/
- **API Docs (Swagger)**: http://localhost:8000/api/v1/docs
- **Health Check**: http://localhost:8000/api/v1/health

### Option B: Local Python (without Docker)

```bash
# 1. Install PostgreSQL and create the database
psql -U postgres -c "CREATE USER sandbox WITH PASSWORD 'sandbox_dev_password_change_me';"
psql -U postgres -c "CREATE DATABASE sandbox_db OWNER sandbox;"
psql -U sandbox -d sandbox_db -f src/database/schema.sql

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Set environment
cp .env.example .env
# Edit DATABASE_URL in .env to match your PostgreSQL connection

# 4. Run
python src/main.py
```

### Option C: Full Production Stack (Docker Compose)

For the full stack including CAPEv2, MISP, Elasticsearch, Falco, and Nginx:

```bash
docker compose --profile full up --build
```

> [!WARNING]
> The `full` profile requires nested virtualization (for CAPEv2/KVM) and significant resources (~16GB RAM minimum). Use this only on a dedicated server or VM.

---

## 2. Authentication

The platform uses API key authentication for the REST API.

On first database initialization, a default admin user is created:
- **Username**: `admin`
- **Password**: `change-me-immediately`

### Generating an API Key

```sql
-- Connect to the database and generate a key for the admin user
UPDATE users
SET api_key_hash = crypt('my-secret-api-key', gen_salt('bf')),
    api_key_expires_at = NOW() + INTERVAL '365 days'
WHERE username = 'admin';
```

You then use this key in all API requests:
```bash
curl -H "Authorization: Bearer my-secret-api-key" http://localhost:8000/api/v1/health
```

The Dashboard pages (/, /samples, /iocs, etc.) do **not** require authentication — they are read-only analyst views.

---

## 3. Submitting Files for Analysis

### Via the REST API (Primary Method)

```bash
# Submit a single file
curl -X POST http://localhost:8000/api/v1/samples \
  -H "Authorization: Bearer my-secret-api-key" \
  -F "file=@/path/to/suspicious_file.exe" \
  -F "priority=8"

# Response:
# {
#   "sample_id": "abc12345-...",
#   "sha256": "e3b0c44...",
#   "status": "queued",
#   "message": "Sample submitted successfully for analysis"
# }
```

```bash
# Submit multiple files at once (batch, up to 100)
curl -X POST http://localhost:8000/api/v1/samples/batch \
  -H "Authorization: Bearer my-secret-api-key" \
  -F "files=@file1.exe" \
  -F "files=@file2.dll" \
  -F "priority=5"
```

### Via the Swagger UI

1. Open http://localhost:8000/api/v1/docs
2. Click **Authorize** → enter your API key
3. Expand `POST /samples` → click **Try it out**
4. Upload a file and set priority → click **Execute**

### Checking Analysis Status

```bash
# Get status of a submitted sample
curl -H "Authorization: Bearer my-secret-api-key" \
  http://localhost:8000/api/v1/samples/{sample_id}

# Get full analysis report (after completion)
curl -H "Authorization: Bearer my-secret-api-key" \
  http://localhost:8000/api/v1/samples/{sample_id}/report
```

### Via the Dashboard

Navigate to http://localhost:8000/samples to see all submitted samples, their status, and verdicts. Click any sample name to view its full analysis detail page including:
- Behavioral observations (API calls, file/registry operations)
- Extracted IOCs (IPs, domains, URLs, mutexes)
- MITRE ATT&CK technique mappings
- eBPF syscall telemetry
- Falco security alerts

---

## 4. Submitting URLs for Browser Isolation

The platform provides Remote Browser Isolation (RBI) via Kasm Workspaces.

```bash
# Create an isolated browser session to visit a suspicious URL
curl -X POST http://localhost:8000/api/v1/isolation/browser \
  -H "Authorization: Bearer my-secret-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://suspicious-site.com",
    "timeout_minutes": 10
  }'
```

> [!NOTE]
> In `simulated` mode (default), this returns a mock session. To use real isolation, set `KASM_MODE=live` in `.env` and configure `KASM_URL`, `KASM_API_KEY`, `KASM_API_SECRET`.

---

## 5. Sanitizing Documents

Convert untrusted PDFs and Office documents into safe, pixel-based PDFs:

```bash
# Sanitize a suspicious document
curl -X POST http://localhost:8000/api/v1/isolation/sanitize \
  -H "Authorization: Bearer my-secret-api-key" \
  -F "file=@suspicious_report.pdf"

# Response includes a download link for the safe PDF
```

> [!NOTE]
> In `simulated` mode, the file is passed through as-is. To use real sanitization, set `DANGERZONE_MODE=live` in `.env` and ensure Dangerzone is installed on the host.

---

## 6. Using the Built-in AI Sandbox

The AI Sandbox lets you execute untrusted code in an ephemeral, isolated environment.

### Execute Code

```bash
curl -X POST http://localhost:8000/api/v1/ai-sandbox/execute \
  -H "Authorization: Bearer my-secret-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "import os; print(os.listdir('.'))",
    "language": "python",
    "timeout_seconds": 30,
    "network_access": false,
    "allowed_domains": [],
    "dependencies": ["requests"]
  }'
```

**Response:**
```json
{
  "execution_id": "abc-123",
  "status": "success",
  "stdout": "['file1.txt', 'file2.py']",
  "stderr": "",
  "execution_time_ms": 2500
}
```

### How It Works
- The code runs inside an **E2B sandbox** (or gVisor container), completely isolated from the host.
- **Network egress** is blocked by default. If `network_access: true`, only `allowed_domains` can be reached.
- The **AI Orchestrator** (`src/ai/orchestrator.py`) enforces a tool denylist — agents cannot call `system_shell`, `read_env_vars`, or `modify_network`.
- All agent outputs are **sanitized** to redact accidentally leaked API keys or secrets.

### Connecting to the Live E2B Service

```env
E2B_MODE=live
E2B_API_KEY=your_e2b_api_key_here
```

Sign up at https://e2b.dev to get an API key.

---

## 7. The Analysis Pipeline (How It All Connects)

When you submit a file, this is what happens end-to-end:

```
File Upload → API (/samples) → PostgreSQL (queued)
                                     ↓
                              Background Worker
                                     ↓
                         1. MISP Pre-Enrichment
                            (checks if hash is already known)
                                     ↓
                         2. CAPEv2 Detonation
                            (runs file in isolated VM)
                                     ↓
                         3. Sigma Rule Matching
                            (matches behaviors against detection rules)
                                     ↓
                         4. ML Classification (XGBoost + SHAP)
                            (scores maliciousness with explanations)
                                     ↓
                         5. eBPF Telemetry + Falco Alerts
                            (kernel-level syscall monitoring)
                                     ↓
                         6. MISP Post-Sync
                            (shares new IOCs back to threat intel)
                                     ↓
                              Dashboard Updated
```

### Starting the Background Worker

The worker is a separate process that polls the queue:

```bash
python src/worker/main.py
```

> [!IMPORTANT]
> The worker requires CAPEv2 to be running. Without it, samples will remain in `queued` status. The dashboard will still show them, but analysis won't progress.

---

## 8. Connecting External Services

Each external service uses the **Abstract Client Pattern** — you switch between `simulated` and `live` mode via environment variables.

| Service | Env Var | Purpose |
|---------|---------|---------|
| **CAPEv2** | `CAPEV2_URL` | Malware detonation sandbox |
| **MISP** | `MISP_URL` | Threat intelligence sharing |
| **E2B** | `E2B_MODE=live`, `E2B_API_KEY` | AI code execution |
| **Kasm** | `KASM_MODE=live`, `KASM_URL`, `KASM_API_KEY` | Browser isolation |
| **Dangerzone** | `DANGERZONE_MODE=live` | Document sanitization |
| **DRAKVUF** | `DRAKVUF_MODE=live`, `DRAKVUF_API_URL` | Hypervisor introspection |

---

## 9. Dashboard Pages

| URL | Description |
|-----|-------------|
| `/` | Overview dashboard with sample statistics |
| `/samples` | Filterable list of all submitted samples |
| `/sample/{id}` | Detailed analysis view (behaviors, IOCs, eBPF, Falco) |
| `/iocs` | Indicators of Compromise extracted from analyses |
| `/mitre-attack` | MITRE ATT&CK technique coverage heatmap |
| `/ai-sandbox` | AI code execution logs |
| `/isolation` | Browser isolation and document sanitization logs |
| `/advanced` | DRAKVUF introspection, Cowrie honeypot, MITRE tagging |

---

## 10. Project Structure

```
sandbox-platform/
├── Dockerfile                    # Unified container image
├── docker-compose.dev.yml        # Minimal: Postgres + Platform
├── docker-compose.yml            # Full stack (CAPEv2, MISP, etc.)
├── .env                          # Your local configuration
├── requirements.txt              # Python dependencies
├── src/
│   ├── main.py                   # Integrated server launcher
│   ├── api/
│   │   ├── submission.py         # REST API (submit, status, reports)
│   │   ├── code_interpreter.py   # AI code execution endpoint
│   │   └── sanitize_document.py  # Document sanitization endpoint
│   ├── frontend/
│   │   ├── dashboard.py          # Dashboard web application
│   │   └── templates/            # HTML templates (Jinja2)
│   ├── worker/
│   │   ├── main.py               # Background analysis worker
│   │   └── evasion_resistance.py # Anti-sandbox-detection engine
│   ├── ai/
│   │   ├── orchestrator.py       # AI agent governance
│   │   └── playbook_generator.py # Automated IR playbook creation
│   ├── ml/
│   │   └── false_positive_classifier.py  # XGBoost + SHAP classifier
│   ├── network/
│   │   └── egress_policy.py      # Dynamic network firewall
│   ├── config/
│   │   ├── auth.py               # Identity provider abstraction
│   │   └── demo_mode.py          # Demo feature flags
│   ├── database/
│   │   └── schema.sql            # PostgreSQL schema
│   ├── infrastructure/
│   │   ├── retention_policy.py   # GDPR data lifecycle management
│   │   ├── honeypot_router.py    # Traffic routing to honeypots
│   │   └── k8s/                  # Kubernetes deployment files
│   └── metrics/
│       └── research_metrics.py   # Academic metric export
├── docs/
│   ├── THREAT_MODEL.md           # STRIDE threat analysis
│   ├── REPRODUCIBILITY.md        # Academic reproducibility guide
│   └── adr/                      # Architecture Decision Records
├── scripts/
│   ├── verify-isolation.sh       # Network isolation verification
│   ├── demo_graduation.sh        # One-click demo launcher
│   └── export_thesis_data.py     # Thesis data bundler
├── tests/
│   └── test_research_validity.py # SHAP consistency + evasion tests
└── vendor/                       # Git submodules (CAPEv2, MISP, etc.)
```
