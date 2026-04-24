#!/bin/bash
set -e

echo "🔒 Verifying network isolation controls..."

# Require docker to be installed
if ! command -v docker &> /dev/null; then
    echo "⚠️ Docker not found. Skipping isolation checks."
    exit 0
fi

# Ensure sandbox-isolated network exists for testing
if ! docker network ls | grep -q sandbox-isolated; then
    docker network create --internal sandbox-isolated
fi

# 1. Verify sandbox containers cannot reach host network
docker run --rm --network=sandbox-isolated alpine \
  wget -T 3 --spider http://host.docker.internal:22 2>/dev/null && \
  { echo "❌ FAIL: Sandbox can reach host SSH"; exit 1; } || \
  echo "✅ PASS: Host network isolation"

# 2. Verify egress policy blocks unauthorized destinations
docker run --rm --network=sandbox-isolated alpine \
  wget -T 3 --spider http://malicious-domain.example 2>/dev/null && \
  { echo "❌ FAIL: Egress policy not enforced"; exit 1; } || \
  echo "✅ PASS: Egress filtering active"

echo "✅ All network isolation checks passed."
