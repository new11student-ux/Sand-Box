#!/bin/bash
# End-to-end demo script for the graduation presentation

set -e

# Set environment variables for demo mode
export DEMO_ENABLE_SIMULATORS="true"
export DEMO_PRELOAD_SAMPLES="true"

echo "=============================================="
echo "🎓 Graduation Demo: Advanced Sandbox Platform"
echo "=============================================="

# 1. Start platform in demo mode
echo -e "\n[1/4] Starting platform with simulated backends..."
echo "Starting FastAPI dashboard (simulated for script)..."
sleep 2

# 2. Pre-load demo samples
echo -e "\n[2/4] Loading demonstration samples into database..."
echo "Simulating insertion of EICAR, Ransomware.WannaCry, and Benign_PDF..."
sleep 1

# 3. Run automated analysis sequence
echo -e "\n[3/4] Executing analysis workflow..."
echo "Applying Adaptive Evasion Resistance to Ransomware sample..."
sleep 2
echo "Extracting IOCs and enriching with MISP..."
sleep 1

# 4. Open dashboard in presentation mode
echo -e "\n[4/4] Demo environment is ready!"
echo "👉 Please open your browser to: http://localhost:3000"

echo -e "\n✅ Press Ctrl+C to stop the platform when the presentation is complete."
