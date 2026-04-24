# Sandbox Platform: Production Runbook

This runbook outlines the operational procedures for managing the Sandbox Platform in a production Kubernetes environment.

## 1. Deployment
To deploy or update the platform:
```bash
bash scripts/deploy-production.sh
```
This script will validate manifests and apply them via Kustomize.

## 2. Monitoring & Observability
- **Grafana**: Available at port `3000`. Default login is `admin / admin123` (change immediately via environment variables).
- **Prometheus**: Scrapes metrics every 15s. Available at port `9090`.
- Key metrics to alert on:
  - High `sandbox_analysis_duration_seconds` (indicates worker bottleneck).
  - High rate of `sandbox_malware_detected_total` (potential outbreak).

## 3. Confidential Computing
If utilizing Enarx for ML Threat Classifiers:
1. Compile the WASM binary: `cargo build --target wasm32-wasi`
2. Deploy the Keep: `enarx run --target sgx src/confidential/Enarx.toml`
3. Refer to `scripts/demo_enarx.sh` for attestation concepts.

## 4. Disaster Recovery
- **Database Backups**: A CronJob runs daily at 2 AM (`k8s/base/postgres-backup-cronjob.yaml`) to dump the database.
- **Restore Procedure**: 
  1. Retrieve the latest `.sql.gz` backup.
  2. Unzip and pipe into Postgres: `zcat backup.sql.gz | psql -U sandbox -h sandbox-postgres sandbox_db`

## 5. Security Posture
- All containers run as non-root (`runAsUser: 1000/999`).
- All Linux capabilities are dropped (`drop: ["ALL"]`).
- Default Seccomp profile is enabled.
- Network policies enforce zero-trust isolation between API, Worker, DB, and Redis pods.
