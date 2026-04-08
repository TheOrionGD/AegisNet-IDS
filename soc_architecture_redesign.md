# Enterprise SOC/SIEM Architecture Redesign (CNS)

This document outlines the architectural shift from a prototype-grade IDS to a scalable, production-ready SIEM/SOC platform. The design prioritizes modularity, event-driven processing, and storage abstraction.

## User Review Required

> [!IMPORTANT]
> This redesign involves moving almost every file in the current `src/` directory. It is a complete structural overhaul meant to support high-throughput event processing and multi-service deployment.

> [!TIP]
> This architecture is designed to be "Kafka-ready." Even if initially using internal queues, the service boundaries are clearly defined to allow moving to a distributed message bus easily.

## Proposed Folder Structure (SIEM-Grade)

```text
cns-root/
├── apps/                        # High-level application entry points
│   ├── api/                     # FastAPI SIEM API (Port 8000)
│   ├── ingester/                # Snort/Network log ingestion engine
│   ├── detector/                # ML Anomaly Detection Service
│   ├── correlator/              # Incident Correlation Engine
│   └── responder/               # SOAR Automation & Response Service
├── core/                        # Shared Enterprise Core (Kernel)
│   ├── messaging/               # Event bus abstraction (Queue/Kafka)
│   ├── models/                  # Unified Pydantic Schemas (CIM-ready)
│   ├── config/                  # Global configuration management
│   ├── security/                # Auth, JWT, and Encryption
│   └── telemetry/               # Logging, Metrics (Prometheus), and Tracing
├── domain/                      # Pure Business Logic Modules (No IO)
│   ├── alerts/                  # Alert normalization logic
│   ├── anomalies/               # ML model wrappers & inference logic
│   ├── correlation/             # Rule-based grouping logic
│   └── hunting/                 # Threat hunting algorithms
├── infrastructure/              # External Integrations & Data Access
│   ├── persistence/             # Repository Pattern (SQLite -> Postgres)
│   │   ├── repositories/        # Concrete repo implementations
│   │   └── migrations/          # Alembic/SQLAlchemy migration scripts
│   ├── snort/                   # Snort rule & log parsing logic
│   └── threat_intel/            # Connectors (MISP, AlienVault, etc.)
├── data/                        # Local state (SQLite DBs, ML Model Files)
├── configs/                     # YAML environment-specific configurations
├── scripts/                     # Deployment and maintenance tools
└── tests/                       # Global test suite
```

---

## Module Responsibilities

### 1. `apps/` (Application Layer)
Individual services that can run as separate containers or processes.
- **`api/`**: Serves the SOC Dashboard. No business logic here, only route definitions and dependency injection.
- **`ingester/`**: Listens to Snort `alert_json` or PCAP streams and pushes to the internal message bus.
- **`correlator/`**: Consumes alerts and groups them into incidents based on timing and IP relationships.

### 2. `core/` (The Kernel)
Foundational code shared across all services.
- **`messaging/`**: A unified interface for event-driven design. Allows switching from `asyncio.Queue` to `Kafka` or `Redis` without changing domain logic.
- **`models/`**: Implements a **Common Information Model (CIM)**. All security events must conform to these schemas before entering the pipeline.

### 3. `domain/` (Business Logic)
The "Brain" of the SIEM.
- **`anomalies/`**: Wraps `Isolation Forest` and `LSTM` logic. It takes normalized data and outputs anomaly scores.
- **`correlation/`**: Pure logic for finding patterns. Does not know about the database—it only knows about objects.

### 4. `infrastructure/` (Technical Details)
Handles communication with the outside world.
- **`persistence/`**: Implements the **Repository Pattern**. Services ask for data via interfaces, and infrastructure provides them using SQLAlchemy/Postgres or SQLite.
- **`threat_intel/`**: Logic for enriching events with external IP reputation data.

---

## Migration Strategy

### Phase 1: Storage & Model Extraction (Immediate)
- Move existing Pydantic models to `core/models`.
- Finalize the `Repository` interface in `infrastructure/persistence` to decouple logic from SQLite.

### Phase 2: Service Extraction (Modularize)
- Move `correlation_engine.py` logic to `domain/correlation`.
- Move `phase4` modules into `apps/responder` and `domain/response`.
- Extract ML logic from `detect.py` into `domain/anomalies`.

### Phase 3: Message Bus Implementation (Event-Driven)
- Introduce a lightweight `core/messaging` layer using `FastAPI` background tasks or `celery` for internal processing.
- Ensure `ingester` -> `correlator` -> `responder` pipeline is purely event-driven.

### Phase 4: Full Deployment
- Configure `Docker` for each app in the `apps/` directory.
- Switch `infrastructure` to use `PostgreSQL` for historical SIEM data and `Redis` for real-time alerting.

## Open Questions

1. Do you want individual Dockerfiles for each service in `apps/` or a single monolithic container for now?
2. Should we prioritize the **Kafka** interface immediately, or start with an in-memory `AsyncIO` bus?
