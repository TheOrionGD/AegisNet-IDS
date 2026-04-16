# AegisNet CNS (Cybersecurity Network System)

A comprehensive, real-time intrusion detection and response system designed for modern network security operations.

## Overview

Our system captures live network traffic using libpcap and performs real-time intrusion detection using Snort, instead of relying on offline or synthetic datasets. It integrates machine learning for anomaly detection, automated response orchestration (SOAR), and a web-based dashboard for monitoring and management.

### Key Features
- **Real-Time IDS**: Leverages Snort 3 with libpcap for live packet capture and rule-based detection.
- **Machine Learning Engine**: Isolation Forest models for anomaly detection on network traffic patterns.
- **SOAR Integration**: Automated incident response workflows.
- **Event Correlation**: Advanced correlation engine for linking alerts across sources.
- **Web Dashboard**: React-based frontend for real-time visualization and management.
- **Distributed Architecture**: Microservices with Redis event bus, PostgreSQL storage, and Kafka messaging.

## Architecture

- **Back-End**: Python/FastAPI services for API, workers, and bridges.
- **Front-End**: React/Vite dashboard.
- **Data Layer**: PostgreSQL, Elasticsearch, Redis.
- **ML Services**: Scikit-learn models for feature engineering and anomaly detection.
- **Ingestion**: Snort bridge for real-time alert forwarding.

## Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- Docker (optional, for containerized deployment)
- Snort 3 (with Npcap on Windows)
- Redis (for event bus)

### Running the System

1. **Install Dependencies**:
   ```bash
   # Back-end
   cd back-end
   pip install -r requirements.txt

   # Front-end
   cd ../front-end
   npm install
   ```

2. **Start Back-End**:
   ```bash
   cd ..
   python run_system.py
   ```
   - Starts API server, workers, and Snort bridge.

3. **Start Front-End**:
   ```bash
   cd front-end
   npm run dev
   ```
   - Access dashboard at http://localhost:5173

4. **Start Snort** (in a separate terminal):
   - **Windows**: `powershell -ExecutionPolicy Bypass -File scripts\run_snort_windows.ps1`
   - **Linux**: `sudo bash scripts/run_snort.sh`

### Docker Deployment
```bash
# Infrastructure (databases)
docker-compose --profile infra up -d

# Core services
docker-compose --profile core up -d
```

## Configuration

- Edit `config/config.yaml` for system settings.
- Environment variables in `.env` file.
- Snort configuration in `config/snort/`.

## Documentation

- [VMware Setup Guide](docs/README_VMWARE.md)
- API documentation available at `/docs` when running.

## License

[Add license information here]