#!/bin/bash
set -e

TARGET=${1:-127.0.0.1}
SERVER_PORT=${2:-8080}

echo "Starting temporary HTTP server on port ${SERVER_PORT}..."
python3 -m http.server ${SERVER_PORT} >/tmp/snort_http_server.log 2>&1 &
SERVER_PID=$!
sleep 2

echo "Running fast local port scan against ${TARGET}..."
sudo nmap -Pn -p 1-100 ${TARGET}

echo "Sending suspicious encoded POST request..."
curl -X POST http://${TARGET}:${SERVER_PORT} \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "payload=%E2%9C%93%20test%20%25%32%30" || true

echo "Generating high connection volume on port ${SERVER_PORT}..."
for i in {1..60}; do
  curl -s -o /dev/null http://${TARGET}:${SERVER_PORT} || true
  sleep 0.05
done

kill ${SERVER_PID} >/dev/null 2>&1 || true

echo "Traffic generation complete. Check /var/log/snort/alert.json for alerts."
