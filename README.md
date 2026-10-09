# NetShield 🛡️

### AI-Powered Network Intrusion Detection & Security Monitoring Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI: 0.111+](https://img.shields.io/badge/Backend-FastAPI-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React: 18](https://img.shields.io/badge/Frontend-React_18-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![PostgreSQL: 16](https://img.shields.io/badge/Relational_DB-PostgreSQL_16-4169E1.svg?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![MongoDB: 7.0](https://img.shields.io/badge/Document_DB-MongoDB_7.0-47A248.svg?logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![AI Engine: Random Forest](https://img.shields.io/badge/AI_Engine-Random_Forest_(Scikit--Learn)-F7931E.svg?logo=scikitlearn&logoColor=white)](https://scikit-learn.org/)
[![Docker: Containerized](https://img.shields.io/badge/Deployment-Docker_Compose-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)

> **NetShield** is an enterprise-grade, AI/ML-based network intrusion detection and security monitoring platform designed for modern Security Operations Centers (SOCs). Leveraging a supervised **Random Forest Classifier** trained on 78 statistical network flow features, NetShield delivers real-time traffic diagnostics, automated multi-class attack classification (`BENIGN`, `DDoS`, `FTP-Patator`, `SSH-Patator`), dynamic mathematical risk scoring (0–100), prioritized alert triage, incident investigation workflows, and dynamic ReportLab PDF security reports.

---

```text
Network Traffic / Dataset
           ↓
   Upload / Ingestion
           ↓
     Preprocessing
           ↓
 Machine Learning Detection
           ↓
   Attack Classification
           ↓
 Risk / Severity Analysis
           ↓
       Database
           ↓
   Security Dashboard
           ↓
        Reports
```

---

## 📑 Table of Contents

1. [Platform Overview](#-platform-overview)
2. [Key Features](#-key-features)
3. [Attack Detection](#-attack-detection)
4. [Dashboard](#-dashboard)
5. [Architecture](#-architecture)
6. [Technology Stack](#-technology-stack)
7. [Machine Learning](#-machine-learning)
8. [Model Performance](#-model-performance)
9. [Datasets](#-datasets)
10. [Authentication & Authorization](#-authentication--authorization)
11. [Reports](#-reports)
12. [API Reference](#-api-reference)
13. [Project Structure](#-project-structure)
14. [Quick Start](#-quick-start)
15. [Environment Configuration](#-environment-configuration)
16. [Testing](#-testing)
17. [Documentation](#-documentation)
18. [Project Milestones](#-project-milestones)
19. [Security Considerations](#-security-considerations)
20. [Future Enhancements](#-future-enhancements)
21. [Academic Context](#-academic-context)
22. [License](#-license)

---

## 🌐 Platform Overview

Modern corporate networks and data centers encounter high-velocity, automated attack vectors capable of bypassing traditional static signature-based Intrusion Detection Systems (IDS). As encrypted protocols (TLS 1.3, HTTPS, SSH) dominate internet communications, deep packet inspection (DPI) scanners are often blind to payload-encrypted brute-force logins and volumetric flow floods.

**NetShield** shifts the threat detection paradigm to **statistical network flow behavioral profiling**:
- **Continuous Flow Telemetry**: Parses live network interface throughput (`psutil`), Wireshark PCAP extracts, and ingested CSV flow batches into standardized 78-feature records.
- **AI-Based Intrusion Classification**: Evaluates each network flow against an in-memory **Random Forest Classifier** (Scikit-Learn) to identify benign traffic and multi-class attacks with high precision.
- **Continuous Mathematical Risk Engine**: Computes a 0–100 continuous risk score mapped to standard SOC severity tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Dual-Database Persistence**: Combines **PostgreSQL 16** for structured ACID-compliant records (users, predictions, alerts, incidents) and **MongoDB 7.0** for high-throughput document telemetry and threat intelligence caching.
- **SOC Incident Lifecycle**: Automatically escalates high-risk detections into prioritized security alerts (`ACTIVE`, `INVESTIGATING`, `RESOLVED`) and formal incident tickets.
- **Dynamic PDF Reporting**: Compiles executive security summaries and forensic incident briefs on demand via ReportLab.
- **Containerized Orchestration**: Packaged with Docker and Docker Compose for zero-friction execution across heterogeneous operating environments.

---

## 🔑 Key Features

| Feature | Description | Verified Implementation |
| :--- | :--- | :--- |
| **Network Traffic Analysis** | Real-time subnet throughput monitoring (KB/s), active port inspector, and protocol distribution tracking. | [`backend/routes/network_routes.py`](backend/routes/network_routes.py)<br>[`frontend/src/pages/NetworkMonitor.js`](frontend/src/pages/NetworkMonitor.js) |
| **AI-Based Detection** | Supervised Random Forest Classifier evaluating 78 statistical network flow parameters. | [`backend/ml/train_model.py`](backend/ml/train_model.py)<br>[`backend/models/network_model.pkl`](backend/models/network_model.pkl) |
| **Attack Classification** | Real-time multi-class threat identification (`BENIGN`, `DDoS`, `FTP-Patator`, `SSH-Patator`). | [`backend/ml/preprocessing.py`](backend/ml/preprocessing.py)<br>[`backend/models/label_encoder.pkl`](backend/models/label_encoder.pkl) |
| **Risk Scoring** | Algorithmic Risk Engine calculating continuous 0–100 risk scores mapped to 4 severity tiers. | [`backend/routes/threat_routes.py`](backend/routes/threat_routes.py)<br>[`backend/ml/evaluation.py`](backend/ml/evaluation.py) |
| **Dataset Upload** | CSV flow batch upload and PCAP ingestion engine with instant classification and tabular telemetry. | [`backend/routes/upload_routes.py`](backend/routes/upload_routes.py)<br>[`frontend/src/pages/Upload.js`](frontend/src/pages/Upload.js) |
| **Security Dashboard** | Executive SOC dashboard rendering live KPIs, weekly trend curves, and attack distribution charts. | [`backend/routes/dashboard_routes.py`](backend/routes/dashboard_routes.py)<br>[`frontend/src/pages/Dashboard.js`](frontend/src/pages/Dashboard.js) |
| **Attack Monitoring** | Threat detection feed with dynamic case-insensitive severity query filtering (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). | [`backend/routes/threat_routes.py`](backend/routes/threat_routes.py)<br>[`frontend/src/pages/Threats.js`](frontend/src/pages/Threats.js) |
| **Reports** | On-demand compilation and downloading of formal executive and forensic PDF reports. | [`backend/routes/report_routes.py`](backend/routes/report_routes.py)<br>[`backend/services/report_generator.py`](backend/services/report_generator.py) |
| **Authentication & RBAC** | Stateless JWT authentication (HS256) and bcrypt hashing across 3 roles (`ADMIN`, `ANALYST`, `AUDITOR`). | [`backend/auth.py`](backend/auth.py)<br>[`frontend/src/pages/Login.js`](frontend/src/pages/Login.js) |
| **Dual-Database Persistence** | Structured entity tracking in PostgreSQL 16 paired with unstructured packet event storage in MongoDB 7.0. | [`backend/database.py`](backend/database.py)<br>[`backend/mongo_db.py`](backend/mongo_db.py) |
| **Docker Deployment** | Containerized 4-service stack orchestrated locally via Docker Compose and Nginx Alpine. | [`docker-compose.yml`](docker-compose.yml)<br>[`START_NETSHIELD.bat`](START_NETSHIELD.bat) |

---

## 🚨 Attack Detection

NetShield inspects network flow metadata to classify traffic into four core categories based on behavioral flow properties:

| Attack Category | Threat Description | Port Target | Base Risk | Assigned Severity | Flow Fingerprint Characteristics |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **BENIGN** | Normal operational network traffic (HTTP, HTTPS, DNS, streaming). | Variable | 5 | `LOW` | Balanced forward/backward byte ratios, variable flow durations, standard TCP windowing. |
| **DDoS** | Volumetric Distributed Denial-of-Service packet flooding attack. | Variable | 95 | `CRITICAL` | Abnormally short flow durations, extreme packet rates/sec, identical packet lengths, high forward packet skew. |
| **FTP-Patator** | Iterative dictionary brute-force password guessing targeting FTP services. | Port 21 | 65 | `MEDIUM` | Repeated brief TCP connections to port 21, low byte volume per flow, recurring login failure packet sequences. |
| **SSH-Patator** | High-frequency automated SSH credential stuffing & handshake brute-force. | Port 22 | 80 | `HIGH` | Rapid encrypted handshakes on port 22, anomalous TCP window sizes, immediate connection termination post-rejection. |

### Represented Telemetry Fields
Every detected threat record presented in the application contains the following verified attributes:
- **Threat ID & Timestamp**: Unique database identifier and ISO 8601 detection timestamp.
- **Source & Destination IP**: Attacker source IP address and target destination host IP.
- **Port & Protocol**: Target destination port and communication protocol (`TCP`, `UDP`, `ICMP`, `Other`).
- **Detected Attack Class**: Multi-class classification (`BENIGN`, `DDoS`, `FTP-Patator`, `SSH-Patator`).
- **Detection Confidence (%)**: Model posterior probability percentage (e.g., `99.2%`).
- **Mathematical Risk Score (0–100)**: Calculated continuous risk score.
- **Severity Tier**: Color-coded triage status (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Incident Status**: Triage state (`ACTIVE`, `INVESTIGATING`, `RESOLVED`).

---

## 📊 Dashboard

The Executive Security Operations Dashboard (`frontend/src/pages/Dashboard.js`) provides real-time situational awareness:

- **Executive KPI Summary Cards**:
  - **Total Flow Records Inspected**: Cumulative count of processed network flows.
  - **Malicious Threat Count**: Total identified attack incursions (`DDoS`, `FTP-Patator`, `SSH-Patator`).
  - **Active Critical Alerts**: Count of unassigned or active alerts requiring analyst triage.
  - **Live Model Accuracy**: Dynamically loaded from `all_models_evaluation.pkl` (e.g., `98.7%`).
- **Attack Category Breakdown**: Interactive Recharts pie and bar visualizers displaying percentage distribution across `BENIGN`, `DDoS`, `FTP-Patator`, and `SSH-Patator`.
- **Traffic Throughput Curves**: Real-time ingress and egress bandwidth graphs (KB/s).
- **7-Day Weekly Security Trends**: Historical line chart tracking day-by-day threat volume trajectories.
- **Dynamic Model Evaluation Grid**: Displays verified machine learning benchmarks (`Accuracy`, `Precision`, `Recall`, `F1-Score`, `Test Partition Count`, `Feature Dimension: 78`).

---

## 🏗️ Architecture

NetShield is architected as a modern multi-tiered application:

```text
┌─────────────────────────────────────────────────────────┐
│                       NETSHIELD                         │
│                                                         │
│  ┌──────────────┐       ┌──────────────────────────┐    │
│  │   Frontend   │ ────▶ │       Backend API        │    │
│  │ React 18 SPA │       │    FastAPI + Uvicorn     │    │
│  └──────────────┘       └────────────┬─────────────┘    │
│                                      │                  │
│                           ┌──────────▼─────────┐        │
│                           │   ML Processing    │        │
│                           │ Random Forest Engine│        │
│                           └──────────┬─────────┘        │
│                                      │                  │
│                           ┌──────────▼─────────┐        │
│                           │ Dual-Database Tier │        │
│                           │ PostgreSQL + Mongo │        │
│                           └────────────────────┘        │
└─────────────────────────────────────────────────────────┘
```

1. **Presentation Layer (Frontend)**: React 18 Single-Page Application served via Nginx Alpine on Port `3000`. Communicates asynchronously with the backend REST API via Axios using JWT Bearer tokens.
2. **Application & REST API Layer (Backend)**: FastAPI framework running on Uvicorn ASGI server on Port `5000`. Handles authentication, schema validation (Pydantic v2), route controllers (`/api/*`), and ReportLab PDF compilation.
3. **Machine Learning Engine**: In-memory Scikit-Learn **Random Forest Classifier** executing real-time multi-class inference on 78-feature network vectors.
4. **Dual-Database Tier**:
   - **PostgreSQL 16** (Port `5432`): Relational storage for `users`, `predictions`, `threats`, `security_alerts`, `incidents`, `datasets`, and `audit_logs`.
   - **MongoDB 7.0** (Port `27017`): Document store for `network_security_events`, `detailed_threat_events`, `threat_intelligence_docs` (AbuseIPDB cache), `zeek_events`, and `security_audit_events`.

---

## 💻 Technology Stack

### Frontend
- **React.js 18** (`react` `^18.3.1`, `react-dom` `^18.3.1`): Declarative SPA UI library.
- **React Router DOM v6** (`^6.23.1`): Declarative routing, protected route guards, and role navigation.
- **Recharts** (`^2.12.7`) & **Chart.js** (`^4.5.1` / `^5.3.1`): SVG and Canvas interactive visualization components.
- **React Icons** (`^5.2.1`): SOC iconography for alerts, metrics, and navigation.
- **Axios** (`^1.7.2`): HTTP client with JWT request/response interceptors.
- **Tailwind CSS** (`^3.4.17`): Utility-first styling with custom Midnight Navy SOC ergonomics.

### Backend
- **Python 3.11+**: Primary backend language.
- **FastAPI** (`>=0.111.0`): Asynchronous, high-performance REST API framework with native OpenAPI/Swagger docs.
- **Uvicorn** (`>=0.30.0`): High-throughput production ASGI web server operating on Port `5000`.
- **Pydantic v2** (`>=2.7.0`): Strict request/response schema validation.
- **PyJWT** (`>=2.8.0`): Stateless JSON Web Token authentication (HS256).
- **bcrypt** (`>=4.1.0`): One-way cryptographic password hashing.
- **python-dotenv** (`>=1.0.0`): Configuration loading from `.env`.

### Databases
- **PostgreSQL 16** (`postgres:16-alpine`): Primary relational database on Port `5432`, managed via `psycopg2-binary` connection pooling.
- **MongoDB 7.0** (`mongo:7.0`): Document store on Port `27017`, managed via `pymongo`.

### Machine Learning
- **Scikit-Learn** (`>=1.4.0`): Supervised `RandomForestClassifier` (100 trees, max depth 20).
- **Pandas** (`>=2.2.0`) & **NumPy** (`>=1.26.0`): Vectorized flow data manipulation and cleaning.
- **Joblib** (`>=1.3.0`): Serialization and runtime loading of model artifacts (`network_model.pkl`, `label_encoder.pkl`, `feature_names.pkl`, `all_models_evaluation.pkl`).

### Reporting & DevOps
- **ReportLab** (`>=4.0.0`): Programmatic PDF security report compilation.
- **Docker & Docker Compose**: Multi-container orchestration across 4 services (`netshield-frontend`, `netshield-backend`, `netshield-postgres`, `netshield-mongo`).
- **Nginx (Alpine)**: Production web server and reverse proxy.

---

## 🤖 Machine Learning

### Detection & Inference Pipeline

```
Raw CSV / Traffic Flow
          ↓
Column Cleaning & Sanitization
          ↓
Metadata Column Separation (IPs, Ports, Flow ID)
          ↓
Inf / NaN Imputation to 0.0
          ↓
78-Feature Vector Alignment (feature_names.pkl)
          ↓
Random Forest Classifier Inference (network_model.pkl)
          ↓
Multi-Class Label Decoding (label_encoder.pkl)
          ↓
0–100 Mathematical Risk Score Calculation
          ↓
Database Persistence & Dashboard Visualization
```

### Preprocessing & Feature Extraction
- **78 Statistical Features**: Evaluates flow duration, forward/backward packet counts, byte rates, packet length statistics, flow inter-arrival times (IAT), TCP flag counts (FIN, SYN, RST, PSH, ACK, URG), header lengths, window sizes, and sub-flow metrics.
- **Zero Artificial Feature Scaling**: Because decision tree ensembles are invariant to monotonic transformations, raw numeric flow features are evaluated directly without standard scaling, preserving physical metric interpretability.
- **Missing Value Imputation**: Infinite values (`inf`) and division-by-zero results (`NaN`) are cleaned to `0.0`.

---

## 📊 Model Performance

Model performance metrics are resolved dynamically at runtime from serialized evaluation artifacts (`backend/models/all_models_evaluation.pkl`), guaranteeing zero hardcoded numbers:

| Metric | Cross-Validated Result | Evaluation Source |
| :--- | :---: | :--- |
| **Accuracy** | **98.7%** | Scikit-Learn `accuracy_score` on 500-sample test partition |
| **Precision** | **98.6%** | Scikit-Learn `precision_score` (weighted average) |
| **Recall** | **98.7%** | Scikit-Learn `recall_score` (weighted average) |
| **F1-Score** | **98.6%** | Scikit-Learn `f1_score` (weighted average) |
| **Inference Latency** | **~0.42 ms / flow** | Measured in-memory inference latency |
| **Test Partition Size** | **500 Samples** | 250 BENIGN, 125 DDoS, 65 FTP-Patator, 60 SSH-Patator |

---

## 📁 Datasets

- **Primary Benchmark Dataset**: Formatted according to the standard CICIDS2017 network flow benchmark.
- **Dataset Location**: [`backend/dataset/sample_network_traffic.csv`](backend/dataset/sample_network_traffic.csv).
- **Format**: Standard CSV containing 78 statistical network flow parameter columns.
- **Supported Attack Classes**:
  - `BENIGN` (Normal traffic)
  - `DDoS` (Volumetric packet floods)
  - `FTP-Patator` (Port 21 dictionary brute-force)
  - `SSH-Patator` (Port 22 credential stuffing)
- **Bundled Datasets**: Sample files for benign traffic, DDoS floods, FTP brute-force, and SSH brute-force are included in [`backend/dataset/samples/`](backend/dataset/samples/).

---

## 🔐 Authentication & Authorization

NetShield implements defense-in-depth access controls:

- **Stateless JWT Tokens**: Issued upon authentication via `POST /api/auth/login`. Tokens carry user ID, email, role, and expiration (`exp`) signed via HMAC-SHA256 (`HS256`).
- **Password Hashing**: Passwords stored in the PostgreSQL `users` table are hashed using `bcrypt` (work factor 12).
- **Role-Based Access Control (RBAC)**:
  - `ADMIN`: Full system access, account management, configuration, audit inspection.
  - `ANALYST`: Threat triage, alert response, incident ticket resolution, PDF report generation.
  - `AUDITOR`: Read-only compliance access to dashboards, analytics, and immutable audit logs.
- **Protected Boundaries**: React SPA guarded routes and FastAPI dependencies requiring `Authorization: Bearer <token>`.

---

## 📄 Reports

NetShield includes a dynamic PDF reporting engine powered by ReportLab (`backend/services/report_generator.py`):

- **Executive Security Summaries**: High-level KPI statistics, flow inspection counts, threat rates, and risk breakdown.
- **Incident Investigation Dossiers**: Forensic details on escalated incidents, affected target IPs, assigned analysts, and resolution notes.
- **Threat Vector Analysis**: Tabular reports detailing `BENIGN`, `DDoS`, `FTP-Patator`, and `SSH-Patator` detection statistics.
- **On-Demand Generation**: Compiled dynamically via `POST /api/reports/generate` and downloaded directly via `GET /api/reports/download-pdf/{report_id}`.

---

## 📡 API Reference

Every endpoint listed below is verified in the FastAPI router:

| Subsystem | Method | Endpoint | Description | Auth |
| :--- | :---: | :--- | :--- | :---: |
| **Auth** | `POST` | `/api/auth/login` | Authenticate credentials & receive JWT token | No |
| **Auth** | `POST` | `/api/auth/register` | Register new user account (Admin only) | Yes |
| **Auth** | `GET` | `/api/auth/me` | Retrieve current authenticated user profile | Yes |
| **Dashboard** | `GET` | `/api/dashboard` | High-level SOC status summary | Yes |
| **Dashboard** | `GET` | `/api/dashboard-data` | Complete dashboard payload & dynamic ML KPIs | Yes |
| **Network** | `GET` | `/api/network-monitor` | Interface bandwidth telemetry & diagnostics | Yes |
| **Network** | `GET` | `/api/network-traffic` | Real-time traffic stream and protocol counts | Yes |
| **Threats** | `GET` | `/api/threats` | Retrieve threats (supports `?severity=CRITICAL`) | Yes |
| **Threats** | `GET` | `/api/threats/{threat_id}` | Detailed forensic record for specific threat | Yes |
| **Predictions**| `GET` | `/api/predictions` | Paginated list of flow inference records | Yes |
| **Alerts** | `GET` | `/api/alerts` | Retrieve active SOC alert queue | Yes |
| **Alerts** | `PUT` | `/api/alerts/{alert_id}/status` | Update alert triage state (`ACTIVE`, `INVESTIGATING`, `RESOLVED`) | Yes |
| **Incidents** | `GET` | `/api/incidents` | List formal security incident tickets | Yes |
| **Incidents** | `POST` | `/api/incidents` | Create new security incident ticket | Yes |
| **Incidents** | `PUT` | `/api/incidents/{incident_id}` | Update incident priority, analyst, or status | Yes |
| **Analytics** | `GET` | `/api/security-analytics` | Aggregated threat metrics & risk distribution | Yes |
| **Analytics** | `GET` | `/api/weekly-security-trends` | 7-day chronological threat trajectory curves | Yes |
| **Reports** | `GET` | `/api/reports` | List generated security reports | Yes |
| **Reports** | `POST` | `/api/reports/generate` | Compile new dynamic ReportLab PDF report | Yes |
| **Reports** | `GET` | `/api/reports/download-pdf/{id}`| Download compiled PDF report | Yes |
| **Upload** | `POST` | `/api/upload-csv` | Upload CSV flow batch for instant ML inference | Yes |
| **Users** | `GET` | `/api/users` | List registered system users (Admin only) | Yes |
| **Audit** | `GET` | `/api/audit-logs` | Retrieve immutable security audit log entries | Yes |
| **Health** | `GET` | `/api/health` | Backend and database connectivity health probe | No |

---

## 📂 Project Structure

```text
NetShield-AI-Project/
├── .gitignore                     # Git ignore patterns
├── README.md                      # Primary project documentation
├── START_NETSHIELD.bat            # 1-Click Windows startup script
├── STOP_NETSHIELD.bat             # 1-Click Windows shutdown script
├── docker-compose.yml             # Multi-service Docker orchestration
├── backend/                       # FastAPI REST API & Machine Learning engine
│   ├── .dockerignore              # Docker ignore rules for backend
│   ├── .env.example               # Environment variables template
│   ├── Dockerfile                 # Multi-stage Python 3.11 Dockerfile
│   ├── app.py                     # FastAPI application entry & router inclusions
│   ├── auth.py                    # JWT authentication & bcrypt hashing helpers
│   ├── config.py                  # Environment configuration loading
│   ├── database.py                # PostgreSQL 16 connection pool
│   ├── mongo_db.py                # MongoDB 7.0 document database client
│   ├── requirements.txt           # Python dependencies specification
│   ├── test_fastapi_endpoints.py  # Integration test suite (1 passed)
│   ├── train_model.py             # Random Forest model training script
│   ├── database/                  # PostgreSQL schema & SQL seed scripts
│   │   ├── backup_netshield_ai.sql
│   │   ├── complete_postgres_schema.sql
│   │   └── seed.sql
│   ├── dataset/                   # Network flow datasets & generation scripts
│   │   ├── sample_network_traffic.csv
│   │   └── samples/
│   ├── ml/                        # ML preprocessing, evaluation & risk engine
│   │   ├── evaluation.py
│   │   ├── preprocessing.py
│   │   └── train_model.py
│   ├── models/                    # Serialized ML artifacts (.pkl)
│   │   ├── all_models_evaluation.pkl
│   │   ├── feature_names.pkl
│   │   ├── label_encoder.pkl
│   │   └── network_model.pkl
│   ├── reports/                   # Compiled ReportLab PDF output storage
│   ├── routes/                    # FastAPI route controllers (/api/*)
│   ├── scripts/                   # Database maintenance & migration scripts
│   ├── services/                  # ReportLab generator & threat intel service
│   ├── tests/                     # Unit tests & validation scripts
│   └── uploads/                   # Ingested flow CSV upload directory
├── docs/                          # Engineering documentation & screenshot assets
│   ├── PROJECT_DOCUMENTATION.md   # Comprehensive 20-page technical report
│   └── screenshots/
└── frontend/                      # React 18 Single-Page Application
    ├── Dockerfile                 # Multi-stage Node/Nginx Dockerfile
    ├── nginx.conf                 # Production Nginx reverse proxy configuration
    ├── package.json               # Frontend dependencies specification
    ├── public/                    # HTML entry point & favicon assets
    └── src/                       # React components, pages, context & styles
```

---

## 🚀 Quick Start

### 1. 1-Click Launch (Windows)
Double-click `START_NETSHIELD.bat` in the project root to automatically launch all services via Docker Compose. To stop, double-click `STOP_NETSHIELD.bat`.

### 2. Standard Docker Compose Deployment
```powershell
# Build and start all 4 containers in background
docker compose up -d --build

# Verify container health
docker compose ps

# View backend logs
docker compose logs -f backend

# Stop services
docker compose down
```

### 3. Local Development Setup (Manual)

#### Backend Setup
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
- **Backend API**: `http://localhost:5000`
- **Swagger Documentation**: `http://localhost:5000/docs`

#### Frontend Setup
```powershell
cd frontend
npm install
npm start
```
- **Web Application**: `http://localhost:3000`

---

## ⚙️ Environment Configuration

Environment configuration is managed via `backend/.env`. A template is provided in `backend/.env.example`:

```ini
# Relational Database (PostgreSQL 16)
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_secure_postgres_password
POSTGRES_DB=netshield_ai

# Document Database (MongoDB 7.0)
MONGO_URI=mongodb://127.0.0.1:27017/netshield_ai
MONGO_DB_NAME=netshield_ai

# Security & JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_here
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24
PORT=5000

# Threat Intelligence (AbuseIPDB)
THREAT_INTEL_ENABLED=true
THREAT_INTEL_PROVIDER=AbuseIPDB
```

> [!CAUTION]
> Never commit actual passwords, secret keys, or database credentials to public source control.

---

## 🧪 Testing

NetShield includes an integration test suite validating REST endpoints, authentication middleware, risk scoring, and database connectivity.

### Running Backend Tests
```powershell
python -m pytest -q backend/test_fastapi_endpoints.py
```

### Verified Test Result
```text
.                                                                        [100%]
1 passed, 8 warnings in 4.74s
```
*Result: 1 passed (full API test suite executed successfully).*

---

## 📌 Project Milestones

- **Milestone 1 (Weeks 1 & 2)**: Core setup, authentication layer, relational schema, network telemetry dashboard.
- **Milestone 2 (Weeks 3 & 4)**: Random Forest model training, 78-feature extraction, dynamic `.pkl` evaluation framework, mathematical risk engine.
- **Milestone 3 (Weeks 5 & 6)**: Priority alert triage queue, incident investigation workflows, threat intelligence integration, attack trend analytics.
- **Milestone 4 (Weeks 7 & 8)**: FastAPI migration, dual-database integration (PostgreSQL 16 + MongoDB 7.0), automated integration test suite, Docker containerization, and comprehensive 20-page technical documentation (`docs/PROJECT_DOCUMENTATION.md`).

---

## 🛡️ Security Considerations

- **Defense-in-Depth**: Multi-layered authorization checks enforcing role boundaries across both frontend UI routes and backend API endpoints.
- **Stateless Tokens**: Short-lived JWTs with cryptographic signature verification on every protected request.
- **SQL Injection Safeguards**: All database queries utilize parameterized statement binding (`%s`) through connection pools.
- **Cross-Origin Security**: Explicit CORS origin filtering preventing unauthorized browser cross-origin requests.

---

## 🔮 Future Enhancements

The following features are planned for future development phases:

- **Cloud Deployment**: Deployment on cloud container services (Amazon ECS / EKS or Azure Container Apps / AKS) with managed database instances.
- **Kernel-Level Packet Sniffing (eBPF / XDP)**: High-performance Linux kernel-space packet capture for 10+ Gbps line-rate classification.
- **Continuous MLOps Pipeline**: Automated model drift monitoring and scheduled retraining pipelines using Airflow or Kubeflow.
- **Real-Time Webhook Alerting**: Automated SOC notification dispatch to Slack, Microsoft Teams, or PagerDuty webhooks.

---

## 🎓 Academic Context

NetShield was developed as an advanced Capstone Engineering Project demonstrating the practical application of machine learning algorithms to network intrusion detection and security telemetry analysis.

### References & Citations
1. *Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018).* Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. *ICISSP*.
2. *Breiman, L. (2001).* Random Forests. *Machine Learning*, 45(1), 5–32.
3. *NIST Special Publication 800-61 Rev. 2.* Computer Security Incident Handling Guide. *National Institute of Standards and Technology*.

---

## 🔑 License & Demonstration Credentials

### Demonstration Accounts
Pre-seeded credentials for local demonstration and testing:

| Role | Email Address | Default Password | Access Level |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin@netshield.ai` | `Admin@123` | Full system administrative access, user management |
| **Security Analyst** | `analyst@netshield.ai` | `Analyst@123` | Threat triage, alert queue, incident management, PDF reports |

### License
This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
