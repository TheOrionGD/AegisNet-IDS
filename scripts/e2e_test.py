#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, io
# Force UTF-8 on Windows consoles (cp1252 cannot render box-drawing chars)
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
"""
AegisNet SIEM - End-to-End Test Suite
======================================
Tests the full pipeline: API health -> Auth -> Alert Ingestion ->
Analysis Pipeline → Incident Generation → SOAR → WebSocket events.

Usage:
    python scripts/e2e_test.py [--base-url http://localhost:2345]

Prereqs:
    • run_system.py must be running (or at least the SIEM API on port 2345)
    • Virtual env activated: .venv\\Scripts\\activate
"""

import sys
import json
import time
import uuid
import argparse
import asyncio
import threading
import datetime
from pathlib import Path
from typing import Optional

import requests
import websockets  # pip install websockets

BASE_URL = "http://localhost:2345"
WS_URL = "ws://localhost:2345/ws/events"
TIMEOUT = 10  # seconds per HTTP request

# ─────────────────────────────────────────────
# Colours (Windows-safe)
# ─────────────────────────────────────────────
try:
    import colorama; colorama.init(strip=False)
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
except ImportError:
    GREEN = RED = YELLOW = CYAN = BOLD = RESET = ""

PASS_ICON = "[PASS]"
FAIL_ICON = "[FAIL]"
WARN_ICON = "[WARN]"
SEP1 = "=" * 60
SEP2 = "-" * 60

# ─────────────────────────────────────────────
# Test registry
# ─────────────────────────────────────────────
results: list[dict] = []

def record(name: str, passed: bool, detail: str = "", warn: bool = False):
    status = "PASS" if passed else ("WARN" if warn else "FAIL")
    colour = GREEN if passed else (YELLOW if warn else RED)
    results.append({"name": name, "status": status, "detail": detail})
    icon = PASS_ICON if passed else (WARN_ICON if warn else FAIL_ICON)
    print(f"  {colour}{icon} {name}{RESET}  {detail}")

def section(title: str):
    print(f"\n{BOLD}{CYAN}{SEP2}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{SEP2}{RESET}")

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def get(path: str, token: Optional[str] = None, **kw) -> requests.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.get(f"{BASE_URL}{path}", headers=headers, timeout=TIMEOUT, **kw)

def post(path: str, data=None, json_body=None, token: Optional[str] = None, **kw) -> requests.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if data:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return requests.post(f"{BASE_URL}{path}", data=data, json=json_body,
                         headers=headers, timeout=TIMEOUT, **kw)

def make_alert(src_ip="192.168.1.100", dst_ip="10.0.0.1", proto="TCP",
               severity="HIGH", label="Port Scan") -> dict:
    return {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "severity": severity,
        "label": label,
        "pkt_num": str(uuid.uuid4()),
        "src_port": 45321,
        "dst_port": 22,
        "pkt_len": 64,
    }

# ─────────────────────────────────────────────
# Phase 0: API Reachability
# ─────────────────────────────────────────────
def phase_reachability():
    section("Phase 0 · API Reachability")
    try:
        r = get("/")
        passed = r.status_code == 200
        body = r.json() if passed else {}
        record("Root endpoint 200 OK", passed, f"status={r.status_code}")
        if passed:
            record("Root returns 'active' status",
                   body.get("status") == "active",
                   f"status={body.get('status')}")
    except Exception as e:
        record("Root endpoint reachable", False, str(e))
        print(f"\n  {RED}FATAL: API is unreachable at {BASE_URL}.{RESET}")
        print(f"  Start the system with:  python run_system.py\n")
        return False

    try:
        r = get("/docs")
        record("Swagger UI served", r.status_code == 200, f"status={r.status_code}")
    except Exception as e:
        record("Swagger UI served", False, str(e))

    try:
        r = get("/health")
        passed = r.status_code == 200
        body = r.json() if passed else {}
        record("Health endpoint 200 OK", passed, f"status={r.status_code}")
        if passed:
            record("Health status is OK",
                   body.get("status") == "OK",
                   f"got={body.get('status')}")
    except Exception as e:
        record("Health endpoint", False, str(e))

    return True

# ─────────────────────────────────────────────
# Phase 0.5: Shared Services Check
# ─────────────────────────────────────────────
REDIS_UP = False
ES_UP = False

def phase_services():
    global REDIS_UP, ES_UP
    section("Phase 0.5 · Shared Services Check")
    
    # Probe Redis (6379)
    import socket
    try:
        with socket.create_connection(("localhost", 6379), timeout=1):
            REDIS_UP = True
            record("Redis shared bus", True, "localhost:6379")
    except:
        record("Redis shared bus", False, "localhost:6379 unreachable (using per-process stub)", warn=True)

    # Probe ES (9200)
    try:
        r = requests.get("http://localhost:9200", timeout=1)
        ES_UP = r.status_code == 200
        record("Elasticsearch shared storage", ES_UP, "localhost:9200")
    except:
        record("Elasticsearch shared storage", False, "localhost:9200 unreachable (using per-process stub)", warn=True)
    
    return True

# ─────────────────────────────────────────────
# Phase 1: Authentication
# ─────────────────────────────────────────────
def phase_auth() -> Optional[str]:
    section("Phase 1 · Authentication")
    token = None

    # 1a – Create a test user (may already exist, that's fine)
    test_user = f"e2e_{uuid.uuid4().hex[:6]}"
    test_pass = "AegisTest#2026!"
    try:
        r = post("/auth/users/", json_body={"username": test_user,
                                            "email": f"{test_user}@aegis.local",
                                            "password": test_pass})
        if r.status_code == 200:
            record("User registration (POST /auth/users/)", True, f"user={test_user}")
        elif r.status_code == 400:
            record("User registration (POST /auth/users/)", True,
                   f"user={test_user} already exists (OK)")
        else:
            record("User registration (POST /auth/users/)", False,
                   f"HTTP {r.status_code}: {r.text[:120]}")
    except Exception as e:
        record("User registration", False, str(e))

    # 1b – Login with correct credentials
    try:
        r = post("/auth/token",
                 data={"username": test_user, "password": test_pass})
        passed = r.status_code == 200
        record("Login with correct credentials", passed,
               f"HTTP {r.status_code}")
        if passed:
            token = r.json().get("access_token")
            record("JWT access_token present", bool(token), "")
    except Exception as e:
        record("Login", False, str(e))

    # 1c – Login with wrong password
    try:
        r = post("/auth/token",
                 data={"username": test_user, "password": "wrongpassword"})
        record("Login with wrong password returns 401",
               r.status_code == 401,
               f"HTTP {r.status_code}")
    except Exception as e:
        record("Login wrong password", False, str(e))

    # 1d – /auth/users/me with token
    if token:
        try:
            r = get("/auth/users/me", token=token)
            passed = r.status_code == 200
            body = r.json() if passed else {}
            record("GET /auth/users/me with valid JWT", passed,
                   f"username={body.get('username')}")
        except Exception as e:
            record("GET /auth/users/me", False, str(e))

        # 1e – /auth/users/me without token → 401 or 403
        try:
            r = get("/auth/users/me")
            record("GET /auth/users/me without token → 401/403",
                   r.status_code in (401, 403),
                   f"HTTP {r.status_code}")
        except Exception as e:
            record("GET /auth/users/me no-auth", False, str(e))

    return token

# ─────────────────────────────────────────────
# Phase 2: Alert Ingestion
# ─────────────────────────────────────────────
def phase_ingestion() -> list:
    section("Phase 2 · Alert Ingestion")
    ingested_ids = []

    # 2a – Single alert
    alert = make_alert(severity="HIGH", label="Port Scan")
    try:
        r = post("/ingest", json_body=alert)
        passed = r.status_code == 200 and r.json().get("status") in ("published", "ok")
        record("POST /ingest single alert", passed,
               f"status={r.json().get('status') if r.status_code==200 else r.status_code}")
        if passed:
            ingested_ids.append(r.json().get("id"))
    except Exception as e:
        record("POST /ingest single alert", False, str(e))

    # 2b – Batch ingestion (10 alerts)
    batch = [make_alert(src_ip=f"10.1.1.{i}", severity="MEDIUM", label="Brute Force")
             for i in range(10)]
    try:
        r = post("/ingest/batch", json_body=batch)
        passed = r.status_code == 200
        body = r.json() if passed else {}
        count = body.get("count", 0)
        record("POST /ingest/batch (10 alerts)", passed and count == 10,
               f"processed={count}")
    except Exception as e:
        record("POST /ingest/batch", False, str(e))

    # 2c – Malformed alert (no timestamp — should still be accepted, normalised)
    alert_no_ts = {"src_ip": "172.16.0.1", "protocol": "UDP", "severity": "LOW"}
    try:
        r = post("/ingest", json_body=alert_no_ts)
        passed = r.status_code == 200
        body = r.json() if passed else {}
        record("POST /ingest normalises missing timestamp",
               passed and "timestamp" in body,
               f"status={body.get('status')}")
    except Exception as e:
        record("POST /ingest normalise timestamp", False, str(e))

    # 2d – Rate limit stub: send 5 more to check endpoint isn't broken
    errors = 0
    for i in range(5):
        try:
            r = post("/ingest", json_body=make_alert(src_ip=f"10.2.2.{i}"))
            if r.status_code != 200:
                errors += 1
        except Exception:
            errors += 1
    record("Sustained ingestion (5 more alerts, no server error)",
           errors == 0, f"errors={errors}")

    return ingested_ids

# ─────────────────────────────────────────────
# Phase 3: Data Plane — Alerts + Incidents
# ─────────────────────────────────────────────
def phase_data_plane():
    section("Phase 3 · Data Plane")

    # Give the analysis worker a moment to process
    time.sleep(2)

    # 3a – GET /alerts
    try:
        r = get("/alerts")
        passed = r.status_code == 200
        body = r.json() if passed else []
        record("GET /alerts returns 200", passed, f"HTTP {r.status_code}")
        record("GET /alerts returns list", isinstance(body, list),
               f"type={type(body).__name__} len={len(body)}")
    except Exception as e:
        record("GET /alerts", False, str(e))

    # 3b – GET /alerts?limit=5
    try:
        r = get("/alerts?limit=5")
        passed = r.status_code == 200 and isinstance(r.json(), list)
        record("GET /alerts?limit=5 works", passed, f"count={len(r.json()) if passed else '?'}")
    except Exception as e:
        record("GET /alerts?limit=5", False, str(e))

    # 3c – GET /incidents
    try:
        r = get("/incidents")
        passed = r.status_code == 200
        body = r.json() if passed else []
        record("GET /incidents returns 200", passed, f"HTTP {r.status_code}")
        record("GET /incidents returns list", isinstance(body, list),
               f"type={type(body).__name__} len={len(body)}")
    except Exception as e:
        record("GET /incidents", False, str(e))

    # 3d – GET /timeline
    try:
        r = get("/timeline")
        passed = r.status_code == 200
        record("GET /timeline returns 200", passed, f"HTTP {r.status_code}")
    except Exception as e:
        record("GET /timeline", False, str(e))

    # 3e – GET /ips/top
    try:
        r = get("/ips/top")
        passed = r.status_code == 200
        record("GET /ips/top returns 200", passed, f"HTTP {r.status_code}")
    except Exception as e:
        record("GET /ips/top", False, str(e))

    # 3f – GET /anomalies (if route exists)
    try:
        r = get("/anomalies")
        record("GET /anomalies returns 200",
               r.status_code == 200,
               f"HTTP {r.status_code}",
               warn=(r.status_code != 200))
    except Exception as e:
        record("GET /anomalies", False, str(e))

# ─────────────────────────────────────────────
# Phase 4: SOAR / Response Trigger Simulation
# ─────────────────────────────────────────────
def phase_soar():
    section("Phase 4 · SOAR Trigger (CRITICAL Alert)")
    # Inject a CRITICAL severity alert designed to trigger SOAR escalation
    critical_alert = make_alert(
        src_ip="192.0.2.1",    # TEST-NET — RFC 5737 safe
        dst_ip="10.0.0.1",
        proto="TCP",
        severity="CRITICAL",
        label="SQL Injection Attempt",
    )
    critical_alert["confidence"] = 0.99
    critical_alert["threat_score"] = 95

    try:
        r = post("/ingest", json_body=critical_alert)
        passed = r.status_code == 200
        record("CRITICAL alert ingested successfully", passed,
               f"HTTP {r.status_code}")
    except Exception as e:
        record("CRITICAL alert ingest", False, str(e))

    # Flood the same src_ip to trigger correlation → incident
    for i in range(15):
        try:
            post("/ingest", json_body=make_alert(src_ip="192.0.2.1",
                                                  severity="HIGH",
                                                  label="SQL Injection Attempt"))
        except Exception:
            pass

    time.sleep(3)  # Allow analysis worker to correlate

    # Check if an incident was generated
    try:
        r = get("/incidents")
        body = r.json() if r.status_code == 200 else []
        has_incident = any(
            inc.get("src_ip") == "192.0.2.1" or
            "SQL" in str(inc.get("label", "")) or
            "SQL" in str(inc.get("attack_type", ""))
            for inc in body
        )
        # If Redis is up, we EXPECT incident propagation to work.
        # If Redis is down, we accept a warning.
        is_fail = REDIS_UP and not has_incident
        record("Incident generated from CRITICAL flood",
               has_incident,
               f"incidents_total={len(body)}",
               warn=(not has_incident and not REDIS_UP))
        
        if is_fail:
            # Manually fix the last result to be a FAIL instead of WARN
            results[-1]["status"] = "FAIL"
    except Exception as e:
        record("Incident check after CRITICAL flood", False, str(e))

# ─────────────────────────────────────────────
# Phase 5: WebSocket Live Events
# ─────────────────────────────────────────────
def phase_websocket():
    section("Phase 5 · WebSocket Live Events")

    received = []
    ws_error = None

    async def ws_listen():
        nonlocal ws_error
        try:
            async with websockets.connect(WS_URL, open_timeout=5, close_timeout=5) as ws:
                # Ping/pong keepalive
                await ws.send("ping")
                pong = await asyncio.wait_for(ws.recv(), timeout=5)
                received.append(("pong", pong))

                # Wait briefly for any in-flight incident broadcasts
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=4)
                    received.append(("event", msg))
                except asyncio.TimeoutError:
                    pass  # No broadcast in window — that's fine
        except Exception as e:
            ws_error = str(e)

    # Run async listener in this thread
    try:
        asyncio.run(ws_listen())
    except Exception as e:
        ws_error = str(e)

    if ws_error:
        record("WebSocket connection established", False, ws_error)
        return

    ping_ok = any(v == "pong" for _, v in received)
    record("WebSocket ping → pong", ping_ok, "")

    event_received = any(k == "event" for k, _ in received)
    is_fail = REDIS_UP and not event_received
    record("WebSocket live event received",
           event_received,
           f"{'event data received' if event_received else 'no broadcast in window'}",
           warn=(not event_received and not REDIS_UP))
    
    if is_fail:
        results[-1]["status"] = "FAIL"

# ─────────────────────────────────────────────
# Phase 6: Input Sanitisation / Security
# ─────────────────────────────────────────────
def phase_security():
    section("Phase 6 · Input Sanitisation & Security")

    # 6a – Injection via IP field
    injection_alert = make_alert(src_ip="10.0.0.1; rm -rf /")
    try:
        r = post("/ingest", json_body=injection_alert)
        # API should either accept it (and sanitise internally) or return 422
        safe = r.status_code in (200, 422)
        record("Injection attempt in src_ip doesn't crash server",
               safe, f"HTTP {r.status_code}")
    except Exception as e:
        record("Injection attempt handling", False, str(e))

    # 6b – Extremely large payload
    big_alert = make_alert()
    big_alert["label"] = "A" * 100_000
    try:
        r = post("/ingest", json_body=big_alert)
        record("Oversized payload handled without 500",
               r.status_code != 500,
               f"HTTP {r.status_code}")
    except Exception as e:
        record("Oversized payload", False, str(e))

    # 6c – Empty body to /ingest
    try:
        r = post("/ingest", json_body={})
        record("Empty body to /ingest handled gracefully",
               r.status_code in (200, 422),
               f"HTTP {r.status_code}")
    except Exception as e:
        record("Empty body to /ingest", False, str(e))

    # 6d – SQL injection in query param
    try:
        r = get("/alerts?limit=1 OR 1=1--")
        record("SQL injection in query param handled",
               r.status_code in (200, 422),
               f"HTTP {r.status_code}")
    except Exception as e:
        record("SQL injection query param", False, str(e))

# ─────────────────────────────────────────────
# Final Report
# ─────────────────────────────────────────────
def print_report():
    print(f"\n{BOLD}{CYAN}{SEP1}{RESET}")
    print(f"{BOLD}{CYAN}  AEGISNET SIEM - E2E TEST REPORT{RESET}")
    print(f"{BOLD}{CYAN}{SEP1}{RESET}")

    passed = [r for r in results if r["status"] == "PASS"]
    failed = [r for r in results if r["status"] == "FAIL"]
    warned = [r for r in results if r["status"] == "WARN"]

    print(f"\n  Total : {len(results)}")
    print(f"  {GREEN}Passed: {len(passed)}{RESET}")
    print(f"  {YELLOW}Warned: {len(warned)}{RESET}")
    print(f"  {RED}Failed: {len(failed)}{RESET}")

    if failed:
        print(f"\n{BOLD}{RED}  -- Failures --{RESET}")
        for r in failed:
            print(f"  {RED}{FAIL_ICON} {r['name']}{RESET}  {r['detail']}")

    if warned:
        print(f"\n{BOLD}{YELLOW}  -- Warnings --{RESET}")
        for r in warned:
            print(f"  {YELLOW}{WARN_ICON} {r['name']}{RESET}  {r['detail']}")

    verdict = f"{GREEN}ALL TESTS PASSED{RESET}" if not failed else f"{RED}SOME TESTS FAILED{RESET}"
    print(f"\n  Verdict: {BOLD}{verdict}\n")

    # Write JSON report
    report_path = Path(__file__).parent.parent / "logs" / "e2e_report.json"
    report_path.parent.mkdir(exist_ok=True)
    with open(report_path, "w") as f:
        json.dump({
            "run_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "base_url": BASE_URL,
            "summary": {"total": len(results), "passed": len(passed),
                        "failed": len(failed), "warned": len(warned)},
            "results": results
        }, f, indent=2)
    print(f"  JSON report → {report_path}\n")

    return len(failed) == 0

# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
def main():
    global BASE_URL, WS_URL

    parser = argparse.ArgumentParser(description="AegisNet SIEM E2E Test Suite")
    parser.add_argument("--base-url", default="http://localhost:8000",
                        help="Base URL of the SIEM API")
    args = parser.parse_args()

    BASE_URL = args.base_url.rstrip("/")
    WS_URL = BASE_URL.replace("http://", "ws://").replace("https://", "wss://") + "/ws/events"

    print(f"\n{BOLD}{CYAN}  AegisNet SIEM - End-to-End Test Suite{RESET}")
    print(f"  Target: {BASE_URL}")
    print(f"  Time  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    ok = phase_reachability()
    if not ok:
        sys.exit(1)

    phase_services()
    phase_auth()
    phase_ingestion()
    phase_data_plane()
    phase_soar()
    phase_websocket()
    phase_security()

    all_passed = print_report()
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
