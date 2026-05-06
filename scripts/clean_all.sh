#!/bin/bash
# AegisNet SIEM — Complete Localhost Cleanup (Linux/macOS)
# Kills all processes on SIEM-related ports and common services.

set -e

PORTS=(2345 2346 2347 8000 1234 3456 6379 9200 27017)

echo "=== AEGISNET SIEM — LOCALHOST CLEANUP ==="
echo "Target ports: ${PORTS[*]}"
echo

for PORT in "${PORTS[@]}"; do
    if lsof -Pi :$PORT -t >/dev/null 2>&1; then
        echo "[KILL] Port $PORT — terminating processes..."
        PIDS=$(lsof -ti:$PORT)
        for PID in $PIDS; do
            echo "  → Killing PID $PID"
            kill -9 $PID 2>/dev/null || true
        done
    else
        echo "[CLEAN] Port $PORT — already free"
    fi
done

echo
echo "=== VERIFICATION ==="
for PORT in "${PORTS[@]}"; do
    if lsof -Pi :$PORT -t >/dev/null 2>&1; then
        echo "[WARN] Port $PORT — still in use!"
    else
        echo "[OK]   Port $PORT — free"
    fi
done

echo
echo "All SIEM-related ports cleared. Run: python run_system.py"
