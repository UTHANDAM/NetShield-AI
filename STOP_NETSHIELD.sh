#!/usr/bin/env bash

echo "==============================================================================="
echo "                STOPPING NETSHIELD AI SERVICES                                 "
echo "==============================================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/.backend.pid" ]; then
    BACKEND_PID=$(cat "$SCRIPT_DIR/.backend.pid")
    echo "[*] Terminating Backend process (PID $BACKEND_PID)..."
    kill $BACKEND_PID 2>/dev/null || true
    rm -f "$SCRIPT_DIR/.backend.pid"
fi

if [ -f "$SCRIPT_DIR/.frontend.pid" ]; then
    FRONTEND_PID=$(cat "$SCRIPT_DIR/.frontend.pid")
    echo "[*] Terminating Frontend process (PID $FRONTEND_PID)..."
    kill $FRONTEND_PID 2>/dev/null || true
    rm -f "$SCRIPT_DIR/.frontend.pid"
fi

# Fallback kill by port
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
lsof -ti:3000 | xargs kill -9 2>/dev/null || true

echo "[*] NetShield AI services stopped successfully."
