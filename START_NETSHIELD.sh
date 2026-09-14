#!/usr/bin/env bash

echo "==============================================================================="
echo "               NETSHIELD AI - ENTERPRISE SOC PLATFORM                          "
echo "         AI-Powered Network Anomaly Detection & Threat Monitoring              "
echo "==============================================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check Python
if command -v python3 &>/dev/null; then
    PY_CMD=python3
elif command -v python &>/dev/null; then
    PY_CMD=python
else
    echo "[-] Python is not installed or not in PATH."
    exit 1
fi

echo "[*] Using Python: $PY_CMD"
echo "[*] Checking backend dependencies..."
cd "$SCRIPT_DIR/backend"
$PY_CMD -m pip install -q -r requirements.txt

echo "[*] Starting FastAPI Backend on http://0.0.0.0:8000..."
$PY_CMD -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
echo $BACKEND_PID > "$SCRIPT_DIR/.backend.pid"

sleep 3

echo "[*] Starting Next.js Frontend on http://localhost:3000..."
cd "$SCRIPT_DIR/frontend"
npm install --silent
npm run dev &
FRONTEND_PID=$!
echo $FRONTEND_PID > "$SCRIPT_DIR/.frontend.pid"

echo ""
echo "==============================================================================="
echo " NetShield AI is running!"
echo " - Frontend Web UI:    http://localhost:3000"
echo " - Backend API Docs:   http://localhost:8000/docs"
echo " - Live Traffic Stream: ws://localhost:8000/api/traffic/ws"
echo ""
echo " Default Credentials:"
echo "   Administrator: admin@netshield.ai  / Admin@123456"
echo "   SOC Analyst:   analyst@netshield.ai / Analyst@123456"
echo "   Viewer:        viewer@netshield.ai  / Viewer@123456"
echo ""
echo " Run ./STOP_NETSHIELD.sh to stop all running services."
echo "==============================================================================="

wait
