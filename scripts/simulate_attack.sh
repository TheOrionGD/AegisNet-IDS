#!/bin/bash
# CNS Attack Simulation Script
# ----------------------------
# This script triggers Snort 3 alerts by performing common network attacks
# to verify the end-to-end CNS pipeline (Snort -> Bridge -> API -> Worker -> Storage).

TARGET_IP=${1:-"127.0.0.1"}

echo "-------------------------------------------------------"
echo "  CNS: STARTING ATTACK SIMULATION ON $TARGET_IP"
echo "-------------------------------------------------------"

# 1. Reconnaissance (Nmap SYN Scan)
echo "[1/3] Triggering RECON alert... (Nmap SYN Scan)"
sudo nmap -sS -T4 $TARGET_IP > /dev/null

sleep 2

# 2. Service Discovery / Versioning
echo "[2/3] Triggering ENUM alert... (Service Versioning)"
sudo nmap -sV -p 80,443,8000 $TARGET_IP > /dev/null

sleep 2

# 3. Potentially Malicious Payload (HTTP Exploit Attempt)
# Simulating a basic SQL Injection or Path Traversal attempt
echo "[3/3] Triggering DELIVERY alert... (Simulated HTTP Exploit)"
curl -A "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0" \
     "http://$TARGET_IP:8000/?id='OR+1=1--+-../etc/passwd" > /dev/null 2>&1

echo "-------------------------------------------------------"
echo "  SIMULATION COMPLETE"
echo "  Check CNS API logs or Dashboard for detected incidents."
echo "-------------------------------------------------------"
