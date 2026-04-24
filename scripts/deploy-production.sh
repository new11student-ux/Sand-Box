#!/bin/bash
set -e

echo "🚀 Deploying Sandbox Platform to Production"
echo "==========================================="

# 1. Validate all manifests
echo "[1/4] Validating Kubernetes manifests..."
kubectl apply --dry-run=client -k k8s/base/ -o yaml > /dev/null

# 2. Apply with kustomize
echo "[2/4] Applying base configuration..."
kubectl apply -k k8s/base/

# 3. Deploy observability (optional)
if [[ "${DEPLOY_OBSERVABILITY:-false}" == "true" ]]; then
    echo "[3/4] Starting observability stack..."
    docker-compose -f docker/docker-compose.observability.yml --profile observability up -d
else
    echo "[3/4] Skipping observability stack (set DEPLOY_OBSERVABILITY=true to deploy)..."
fi

# 4. Display access information
echo "[4/4] ✅ Deployment initiated!"
echo ""
echo "🔗 Access Points:"
echo "  API:        http://localhost:8000"
echo "  Grafana:    http://localhost:3000 (if observability enabled)"
echo "  Prometheus: http://localhost:9090 (if observability enabled)"
echo ""
echo "📊 Monitor: kubectl get pods -l app=api -w"
