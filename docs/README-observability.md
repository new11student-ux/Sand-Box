# Observability Stack Quick Start

This stack provisions Prometheus and Grafana for enterprise monitoring of the Sandbox Platform.

## Quick Start

```bash
# Start observability stack
docker-compose -f docker/docker-compose.observability.yml --profile observability up -d

# Access dashboards
Grafana: http://localhost:3000 (admin / admin123)
Prometheus: http://localhost:9090
```

## Setup Instructions

1. **Start the main API server** so it can expose metrics on `http://localhost:8000/metrics`.
2. **Start the observability stack** using the command above.
3. Open Grafana and go to **Dashboards → Browse**.
4. You should see the pre-provisioned **Sandbox Platform Overview** dashboard.
