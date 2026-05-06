# AegisNet CNS: Experimental Procedure

This document outlines the systematic procedure for conducting experimental evaluations of the AegisNet Cyber Security Network System (CNS). The goal is to validate the system's detection accuracy, response latency, and overall effectiveness against various network threats.

---

## 1. Experimental Objectives
- **Detection Validation**: Confirm that signature-based (Snort) and anomaly-based (ML) engines correctly identify threats.
- **Response Orchestration**: Verify that the SOAR engine triggers the correct automated responses (e.g., blocking IPs).
- **Latency Measurement**: Quantify the time from packet capture to alert visualization and response.
- **Accuracy Assessment**: Calculate True Positive (TP) and False Positive (FP) rates for the Isolation Forest model.

---

## 2. Infrastructure Setup

### 2.1 Virtual Network Configuration (VMware)
To capture traffic from other VMs, the host or the IDS VM must be in **Promiscuous Mode**.
1. Open **VMware Virtual Network Editor** as Administrator.
2. Select your target network (e.g., `VMnet8`).
3. Ensure **"Connect a host virtual adapter to this network"** is checked.
4. In the IDS VM settings, ensure the Network Adapter is set to the correct VMnet and the host OS has Npcap installed with "WinPcap compatibility mode".

### 2.2 System Initialization
Ensure all core services are running:
```powershell
# 1. Start Infrastructure (Databases, Redis)
docker-compose --profile infra up -d

# 2. Start AegisNet Backend
python run_system.py

# 3. Start React Dashboard
cd front-end
npm run dev

# 4. Start Snort 3 (Administrator terminal)
powershell -ExecutionPolicy Bypass -File scripts\run_snort_windows.ps1
```

---

## 3. Phase 1: Baseline Traffic Generation
Before testing attacks, the system needs to understand "normal" traffic.
1. Run the traffic generator for 10-15 minutes to simulate standard activity (HTTP browsing, DNS queries, small file transfers).
   ```powershell
   python scripts\simulate_network_traffic.py --duration 600 --intensity medium
   ```
2. Monitor the **Dashboard** to ensure no alerts are triggered during this phase (Baseline verification).

---

## 4. Phase 2: ML Model Training
Once baseline data is collected in the database/logs:
1. Trigger the ML training pipeline to generate the Isolation Forest model.
   ```bash
   python back-end/ml_services/train_model.py
   ```
2. Verify that `models/isolation_forest_model.joblib` and `models/scaler.joblib` have been updated.

---

## 5. Phase 3: Attack Simulation
Use the **Threat Simulation Engine (TSE)** to execute controlled attacks. Run these from a separate "Attacker" machine or a different terminal.

### Scenario A: Reconnaissance (Signature-Based)
*Objective: Detect port scanning using Snort rules.*
```bash
python scripts/threat_simulator.py --mode live --target [TARGET_IP] --attack recon
```

### Scenario B: SYN Flood (Anomaly-Based)
*Objective: Detect high-frequency packet bursts via ML.*
```bash
python scripts/threat_simulator.py --mode live --target [TARGET_IP] --attack dos
```

### Scenario C: Web Attack (Signature + Payload)
*Objective: Detect SQL Injection strings in HTTP payloads.*
```bash
python scripts/threat_simulator.py --mode live --target [TARGET_IP] --attack web
```

### Scenario D: C2 Beaconing (Advanced Correlation)
*Objective: Detect periodic low-volume traffic over a long duration.*
```bash
python scripts/threat_simulator.py --mode live --target [TARGET_IP] --attack c2
```

---

## 6. Phase 4: Monitoring and Response
During and after the attacks, perform the following checks:
1. **Live Dashboard**: Confirm that alerts appear in the "Live Alerts" feed within < 2 seconds of the attack.
2. **Correlation Engine**: Check the "Incidents" tab to see if multiple related alerts (e.g., several port scans from the same IP) were correlated into a single Incident.
3. **SOAR Verification**:
   - Check `logs/soar_worker.log`.
   - Verify if the "Attacker IP" has been added to the internal blocklist or if an alert notification was sent.
4. **Graph Analysis**: Use the Timeline view to visualize the attack progression.

---

## 7. Phase 5: Evaluation & Reporting
After the experiment, collect the results for analysis:
1. **Export Logs**: Retrieve the `data/security_events.json` and PostgreSQL `alerts` table.
2. **Performance Metrics**:
   - **Detection Rate**: (Total Detected Attacks / Total Simulated Attacks) * 100
   - **False Positive Rate**: (Total False Alerts / Total Normal Events) * 100
   - **Mean Time to Detect (MTTD)**: Average time from attack start to system alert.
   - **Mean Time to Respond (MTTR)**: Average time from alert to SOAR action.

3. **Cleanup**:
   ```powershell
   powershell -File scripts\clean_all.ps1
   ```

---
**Note**: Always perform experiments in a controlled, isolated network environment. Ensure you have authorization to capture and simulate traffic on the target network.
