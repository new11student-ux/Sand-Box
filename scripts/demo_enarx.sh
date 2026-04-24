#!/bin/bash
# Demonstrates the Enarx deployment workflow without requiring SGX/SEV hardware

set -e

echo "🔐 Enarx Confidential Computing Demo"
echo "====================================="

# 1. Show the configuration
echo -e "\n[1/4] Enarx configuration:"
cat src/confidential/Enarx.toml

# 2. Simulate WASM compilation step (document the real command)
echo -e "\n[2/4] Compiling ML classifier to WASM (simulated):"
echo "  Real command: wapm install -g wasi-sdk && cargo build --target wasm32-wasi"
echo "  ✅ Simulated: ml_classifier.wasm ready"

# 3. Show deployment command structure
echo -e "\n[3/4] Deployment command (requires Enarx CLI + SGX/SEV hardware):"
echo "  enarx run --target sgx src/confidential/Enarx.toml"
echo "  ✅ Simulated: Keep initialized, model loaded securely inside TEE"

# 4. Demonstrate attestation concept
echo -e "\n[4/4] Remote attestation verification (conceptual):"
cat << 'EOF'
  In production:
  1. Enarx Keep generates cryptographic quote of loaded code
  2. Quote sent to verifier service (e.g., Azure Attestation, Intel IAS)
  3. Verifier confirms: "Yes, this is the authentic ml_classifier.wasm"
  4. Only then is sensitive data (model weights, threat intel) decrypted and sent to the Keep
  
  ✅ Demo: Showing attestation flow diagram
EOF

echo -e "\n📚 Learn more about Confidential Computing: https://enarx.dev/docs"
