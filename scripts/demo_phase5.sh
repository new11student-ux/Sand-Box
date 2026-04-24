#!/bin/bash
# Phase 5 End-to-End Demo Script

echo "🔐 Phase 5 Advanced Features Demo"
echo "=================================="

# Check if the API is running
curl -s http://localhost:8000/api/v1/health > /dev/null
if [ $? -ne 0 ]; then
    echo "❌ Error: API server is not running on localhost:8000. Please start it using 'python src/demo_launcher.py' first."
    exit 1
fi

TOKEN="demo_token_not_secure_in_production"
COWRIE_TOKEN="dev_token_123"
SAMPLE_ID="demo-hash-12345"

# 1. Submit sample for DRAKVUF analysis
echo -e "\n[1/4] Submitting sample to DRAKVUF..."
curl -s -X POST "http://localhost:8000/api/v1/advanced/drakvuf/submit?sample_id=$SAMPLE_ID" \
  -H "Authorization: Bearer $TOKEN" \
  | grep -o '"job_id":"[^"]*' | cut -d'"' -f4 | while read JOB_ID; do
  echo "✅ DRAKVUF Job Created: $JOB_ID"
done

# 2. Simulate honeypot attack
echo -e "\n[2/4] Simulating Cowrie honeypot event (File Download)..."
curl -s -X POST http://localhost:8000/api/v1/advanced/cowrie/webhook \
  -H "X-Cowrie-Token: $COWRIE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "eventid": "cowrie.session.file_download",
    "src_ip": "192.168.1.100",
    "session": "sim_session_123",
    "shasum": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
    "url": "http://evil.com/payload.exe"
  }'
echo -e "\n✅ Honeypot event ingested successfully"

# 3. Show MITRE tagging in action
echo -e "\n[3/4] Running MITRE ATT&CK automated tagging..."
curl -s -X POST "http://localhost:8000/api/v1/advanced/mitre/tag?sample_id=$SAMPLE_ID" \
  -H "Authorization: Bearer $TOKEN"
echo -e "\n✅ MITRE Engine executed."

# 4. Display unified dashboard
echo -e "\n[4/4] Opening advanced dashboard..."
echo "👉 Visit: http://localhost:8000/advanced"
echo -e "\n✅ Demo complete! Review the MITRE matrix and honeypot map in the UI."
