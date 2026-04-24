# Real-Life Testing Guide

This guide covers how to transition the Sandbox Platform from "Demo Mode" (which uses mocked data) to **Live Mode**, connecting to actual infrastructure.

## Prerequisites

To test the platform realistically, you need:
1. Docker & Docker Compose (for PostgreSQL & Observability).
2. API Keys for external integrations (see below).

## Step 1: Provision the Database

The live platform requires a real PostgreSQL instance.

1. Start the database using the provided docker-compose configuration:
```bash
docker-compose up -d postgres
```

2. Apply the schema:
```bash
# Connect to the running postgres container and apply the schema
cat src/database/schema.sql | docker exec -i sandbox-postgres psql -U sandbox -d sandbox_db
```

## Step 2: Configure Environment Variables

1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Open `.env` and configure your API keys.

### Acquiring API Keys

- **E2B (AI Sandboxing)**: Register at [e2b.dev](https://e2b.dev/) to obtain an `E2B_API_KEY`.
- **Kasm (Browser Isolation)**: You must deploy a Kasm Workspaces instance. Follow the [Kasm documentation](https://kasmweb.com/docs/latest/index.html) to deploy, then generate an API key from the Kasm Admin Dashboard.
- **DRAKVUF**: Deploy DRAKVUF on a Xen hypervisor. Refer to [drakvuf.com](https://drakvuf.com/).
- **Cowrie**: Deploy a Cowrie honeypot and configure its webhook output plugin to point to `http://<your-ip>:8000/api/v1/advanced/cowrie/webhook` using the `COWRIE_WEBHOOK_TOKEN` defined in your `.env`.

> [!NOTE]
> If you are missing an API key for a specific service, you can leave its mode as `simulated` in the `.env` file (e.g., `KASM_MODE=simulated`). The platform gracefully handles mixed modes!

## Step 3: Run the Live Server

Instead of using `demo_launcher.py`, start the real production launcher:

```bash
python src/main.py
```

This will boot the integrated FastAPI server (Dashboard + API) on `http://127.0.0.1:8000`.

## Step 4: Verify Live Telemetry

1. Submit a real sample through the UI.
2. Watch the terminal logs—you should see actual external API calls instead of simulated delays.
3. Start the observability stack to monitor real-time metrics:
```bash
docker-compose -f docker/docker-compose.observability.yml --profile observability up -d
```
4. Access Grafana at `http://127.0.0.1:3000` to view live API request rates and malware detection metrics.
