# AegisNet CNS - System Analysis Document

## PROJECT INTRODUCTION

AegisNet CNS (Cybersecurity Network System) is an advanced, real-time Security Information and Event Management (SIEM) platform integrated with Intrusion Detection System (IDS) capabilities. The system leverages Snort 3 for rule-based intrusion detection on live network traffic captured via libpcap/Npcap, enhanced by machine learning-driven anomaly detection using Isolation Forest algorithms. It provides comprehensive threat detection, event correlation, automated Security Orchestration, Automation, and Response (SOAR), and a modern web-based dashboard for security operations.

Designed for modern enterprise environments, including virtualized setups like VMware on Windows 11, AegisNet CNS addresses the need for proactive network security in dynamic, high-volume traffic scenarios. The project features a microservices architecture with Python/FastAPI backend, React/Vite frontend, and support for distributed data stores (PostgreSQL, MongoDB Atlas, Elasticsearch, Redis event bus, Kafka).

## ABSTRACT

AegisNet CNS represents a next-generation cybersecurity solution combining signature-based detection (Snort), unsupervised ML anomaly detection, SIEM correlation, and SOAR automation. Live packet capture ensures zero-delay threat visibility, while adaptive ML models (contamination=0.05, anomaly threshold=-0.45) identify subtle deviations in traffic patterns. The system processes alerts in real-time via Redis pub/sub, correlates events over 5-minute windows, and orchestrates responses (in safe mode by default).

Key differentiators include VMware-optimized promiscuous mode capture, IP reputation checks, threat intel integration (NVD API), and a responsive React dashboard with WebSocket live updates for alerts, anomalies, incidents, timelines, and top IPs. Deployable via Docker Compose, it scales from development to production, supporting Windows/Linux/VM environments.

This document analyzes objectives, challenges, tech stack, architecture, modules, and future roadmap.

## PROJECT OBJECTIVE

- **Primary**: Develop a production-ready, real-time IDS/SIEM with ML augmentation for enterprise network security.
- **Detection**: Achieve high-fidelity threat detection via hybrid rule-ML approach, minimizing false positives.
- **Response**: Automate incident mitigation through SOAR workflows.
- **Usability**: Provide intuitive dashboard for SOC analysts.
- **Scalability**: Support distributed deployment with containerization.
- **Compatibility**: Seamless operation in virtualized (VMware) and physical environments.
- **Performance**: Sub-second anomaly scoring on streaming traffic.

## PROBLEM STATEMENT

Traditional IDS/SIEM systems suffer from:
- **Offline Analysis**: Reliance on pcap dumps or logs delays response.
- **Signature Gaps**: Zero-day/evasive attacks evade rules.
- **Alert Fatigue**: High false positives overwhelm analysts.
- **Siloed Data**: Poor correlation across sources.
- **Scalability Limits**: Struggles with 10Gbps+ traffic.
- **Virtualization Challenges**: VMware adapters ignore promiscuous mode without config.
- **Manual Response**: Slow triage/remediation.
- **Legacy UIs**: Poor real-time visualization.

AegisNet CNS solves these with live capture, unsupervised ML, correlation engines, SOAR, and modern UI.

## PYTHON LIBRARIES USED

Core dependencies from `back-end/requirements.txt`:

| Library | Version | Purpose |
|---------|---------|---------|
| scikit-learn | >=1.3.0 | Isolation Forest anomaly detection, model training/evaluation |
| pandas | >=2.0.0 | Data processing, feature engineering |
| numpy | >=1.24.0 | Numerical computations, array operations |
| scipy | >=1.10.0 | Statistical functions, optimization |
| fastapi | >=0.103.0 | REST/WebSocket API server |
| uvicorn | >=0.23.2 | ASGI server |
| sqlalchemy | >=2.0.0 | ORM for PostgreSQL/SQLite |
| pymongo/motor | >=4.5.0/>=3.3.0 | MongoDB async/sync operations |
| redis | >=5.0.0 | Event bus, caching |
| aiokafka | >=0.8.1 | Kafka messaging bridge |
| elasticsearch | >=8.10.0 | SIEM indexing/search |
| scapy | >=2.5.0 | Packet parsing/analysis |
| websockets | >=12.0 | Real-time client comms |
| python-jose, passlib | - | JWT auth, bcrypt hashing |
| watchdog | >=3.0.0 | File monitoring (Snort alerts) |
| psutil | >=5.9.0 | System monitoring |
| pyyaml, pydantic-settings | - | Config loading |
| joblib | >=1.3.0 | Model persistence |
| networkx | >=3.1 | Graph-based correlation? |
| matplotlib | >=3.7.0 | ML evaluation plots |
| requests, python-multipart | - | HTTP clients, form parsing |
| ipaddress | >=1.0.23 | IP manipulation |

## EXISTING SYSTEM

Conventional solutions:
- **Snort/Suricata**: Excellent rule-based IDS but blind to novel anomalies.
- **ELK Stack**: Log-centric SIEM, not optimized for pcap.
- **Splunk**: Expensive, proprietary.
- **OpenSIEM**: Limited ML integration.
- **Commercial (CrowdStrike, etc.)**: Cloud-only, high cost.

Limitations: Reactive (post-breach), high TCO, poor virtualization support.

## PROPOSED SYSTEM

AegisNet CNS hybrid:
- **Ingestion**: Live Snort alerts → bridge → Redis.
- **Detection**: Rules + ML (features: windowed stats, IP rep).
- **Analysis**: Correlation (5-min windows, severity thresholds), threat intel.
- **Storage**: MongoDB events, ES indexes, Postgres metadata.
- **Response**: SOAR worker (quarantine/block, safe mode).
- **UI**: React dashboard (alerts/anomalies/incidents live).
- **ML Retrain**: Feedback loop for adaptive learning.

Configurable via YAML; Docker-deployable.

## PROPOSED SYSTEM ARCHITECTURE

```
+-------------------+     +-------------------+     +-------------------+
|   Snort 3 +       |     |   React/Vite UI   |     |   Analysts/SOC    |
|   Npcap/libpcap   |<--->|  (WS + REST)      |<--->|                   |
+-------------------+     +-------------------+     +-------------------+
          |                         ^
          v                         |
    +-----------+                   | Redis Event Bus
    | Alert     |                   |
    | Bridge    |-------------------+
    +-----------+
          |
    +-----------+     +-------------------+     +-------------------+
    | FastAPI   |<--->| ML Services       |<--->| SOAR/Analysis     |
    | API + WS  |     | (Isolation Forest)|     | Workers           |
    +-----------+     +-------------------+     +-------------------+
          |                         ^
          v                         |
+-------------------+     +-------------------+     +-------------------+
| MongoDB/          |<--->| PostgreSQL /     |<--->| Elasticsearch     |
| Postgres          |     | SQLite            |     | (SIEM Index)      |
+-------------------+     +-------------------+     +-------------------+
                              | Kafka Bridge (optional scale)
```

**Layers**:
- **Capture**: Snort on VMnet promiscuous.
- **Processing**: Workers (analysis, stream, realtime_ml).
- **Storage**: Hybrid SQL/NoSQL/ES.
- **Services**: Auth/RBAC, repos (mongo/sqlite).

## MODULE DESCRIPTION

| Module/Path | Description |
|-------------|-------------|
| **back-end/api/** | FastAPI main, routes (alerts/anomalies/auth/incidents/websocket), services, models (User/SecurityEvent), repos. |
| **back-end/core/** | Workers (analysis/soar/snort_bridge/stream_processor), pipelines (siem/realtime_ml), event_bus, feedback_loop, ip_reputation. |
| **back-end/ml_services/** | Train/evaluate Isolation Forest, feature_eng, data_loader, simulate_anomalies. |
| **back-end/siem/** | Correlation_engine, threat_intel/hunting/defs, security_posture, storage. |
| **front-end/src/** | React pages (Dashboard/Alerts), hooks (useAlerts/useSocket/etc.), components/UI. |
| **config/** | YAML config, Snort rules/lua. |
| **docker/** | Compose, Dockerfiles (nginx/frontend/backend). |
| **scripts/** | run_snort, simulate_attack/traffic, quick_start. |
| **models/** | joblib Isolation Forest + scaler. |

## CONCLUSION AND FUTURE ENHANCEMENT

AegisNet CNS delivers robust, real-time network security surpassing traditional systems via ML-Snort synergy and automation.

**Achievements**:
- Live detection/response.
- Scalable microservices.
- Cross-platform (Win/VM/Linux).

**Future Enhancements**:
- **DL Models**: LSTM/Transformers for sequence anomalies.
- **Multi-Tenant**: RBAC expansion.
- **Cloud Native**: K8s Helm charts.
- **Enrichment**: VirusTotal/MISP intel.
- **Mobile App**: React Native.
- **Federated Learning**: Privacy-preserving model updates.
- **Quantum-Resistant Crypto**: Post-quantum JWT.
