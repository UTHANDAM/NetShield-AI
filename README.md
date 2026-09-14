# 🛡️ NetShield AI — Enterprise SOC & AI-Powered Network Anomaly Detection System

![FastAPI](https://img.shields.io/badge/Backend-FastAPI%200.115-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Next.js](https://img.shields.io/badge/Frontend-Next.js%2014-000000?style=for-the-badge&logo=nextdotjs&logoColor=white)
![XGBoost](https://img.shields.io/badge/AI%2FML-XGBoost%20%2B%20Scikit--Learn-FF6600?style=for-the-badge&logo=scikitlearn&logoColor=white)
![Docker](https://img.shields.io/badge/Deployment-Docker%20Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red?style=for-the-badge)

NetShield AI is a state-of-the-art, enterprise-ready Security Operations Center (SOC) platform for real-time network anomaly detection, automated incident triage, threat intelligence correlation, and 1-click SOAR (Security Orchestration, Automation, and Response) remediation.

---

## 🌟 Key Features

- **🧠 Dual Machine Learning Inference Pipeline**:
  - Trained on benchmark cybersecurity datasets: **CIC-IDS-2017** (70 features) and **UNSW-NB15** (42 features).
  - High-performance binary and multiclass classifiers powered by **XGBoost** with >99% ROC-AUC.
- **⚡ Live Network Telemetry & Attack Simulation**:
  - Sub-second WebSocket stream (`ws://localhost:8000/api/traffic/ws`) streaming live packet metrics.
  - Interactive Attack Simulation triggers for **DDoS**, **SYN Port Scans**, **SSH Password Spraying**, and **SQL Injection**.
- **🚨 Incident Correlation & 1-Click SOAR Playbooks**:
  - Automated alert correlation into cohesive incidents with MTTR and SLA tracking.
  - Automated remediation actions: **Block IP**, **Isolate Host**, **Rate Limit**, **Revoke Session**, and **Forensic Capture**.
- **🎯 Threat Intelligence & MITRE ATT&CK Matrix**:
  - Interactive 14-tactic MITRE ATT&CK enterprise matrix mapped to active alerts and SIEM rules.
  - IOC database with threat reputation scores for IPs, domains, SHA-256 hashes, and CVEs.
  - SIEM / NIDS detection rule management with custom signature authoring.
- **📊 SOC Executive & Forensic PDF Reports**:
  - Automated PDF report generator with executive summaries, KPI trends, and audit logs powered by ReportLab.
- **🚀 Zero-Friction 1-Click Deployment**:
  - Windows (`START_NETSHIELD.bat`), Linux/macOS (`START_NETSHIELD.sh`), and Docker Compose (`docker-compose up --build`).

---

## ⚡ Quick Start

### 1. One-Click Launch (Windows)
Double-click `START_NETSHIELD.bat` or run in terminal:
```cmd
START_NETSHIELD.bat
```
- Starts FastAPI Backend on `http://localhost:8000`
- Starts Next.js Frontend on `http://localhost:3000`
- Automatically opens your default browser to the web console.
- To stop: Run `STOP_NETSHIELD.bat`.

### 2. One-Click Launch (Linux / macOS)
```bash
chmod +x START_NETSHIELD.sh STOP_NETSHIELD.sh
./START_NETSHIELD.sh
```
- To stop: Run `./STOP_NETSHIELD.sh`.

### 3. Docker Compose Deployment
```bash
docker-compose up --build -d
```

---

## 🔑 Default Credentials

| Role | Email | Password | Permissions |
|------|-------|----------|-------------|
| **Administrator** | `admin@netshield.ai` | `Admin@123456` | Full system access, user & rule management, SOAR execution |
| **SOC Analyst** | `analyst@netshield.ai` | `Analyst@123456` | Incident triage, timeline notes, alert disposition, reports |
| **Security Viewer** | `viewer@netshield.ai` | `Viewer@123456` | Read-only telemetry, dashboards, and report downloads |

---

## 🏗️ Architecture Overview

```
NetShield AI
├── backend/
│   ├── app/
│   │   ├── api/routes/       # REST API endpoints (auth, traffic, alerts, incidents, rules, ml, reports)
│   │   ├── core/             # JWT Auth, security, settings config
│   │   ├── ml/               # Dual ML models (CIC-IDS-2017 & UNSW-NB15) + preprocessors
│   │   ├── models/           # SQLAlchemy ORM database models & Pydantic schemas
│   │   └── services/         # ML inference engine, seed data, PDF generator, SOAR automation
│   ├── tests/                # Automated pytest test suite (100% pass rate)
│   ├── Dockerfile            # Container definition for FastAPI backend
│   └── requirements.txt      # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── app/              # Next.js 14 App Router dashboard & authentication views
│   │   ├── components/       # Modern SOC UI components, KPI cards, Recharts, modals
│   │   └── lib/              # API client and utility helpers
│   ├── Dockerfile            # Multi-stage production container definition
│   └── package.json          # Node dependencies
├── docs/                     # Full technical documentation suite
│   ├── ARCHITECTURE.md       # Detailed system architecture and data flows
│   ├── API_REFERENCE.md      # REST & WebSocket API specification
│   ├── DEPLOYMENT_GUIDE.md   # Deployment instructions (local, docker, nginx)
│   ├── ML_MODEL_REPORT.md    # Training metrics, cross-validation, ROC-AUC details
│   └── USER_MANUAL.md        # SOC analyst operations and triage guide
├── START_NETSHIELD.bat       # Windows 1-click launcher
├── STOP_NETSHIELD.bat        # Windows shutdown script
├── START_NETSHIELD.sh        # Linux/macOS 1-click launcher
├── STOP_NETSHIELD.sh        # Linux/macOS shutdown script
└── docker-compose.yml        # Multi-container orchestration
```

---

## 🧪 Automated Testing

Run the comprehensive pytest test suite:
```bash
cd backend
py -3.12 -m pytest tests/ -v
```
**Results**: `20 passed in 3.10s (100% pass rate)` covering authentication, ML inference, alert triage, incident lifecycles, SOAR execution, and PDF generation.

---

## 📚 Technical Documentation

For in-depth guides, consult the [`docs/`](file:///docs/) directory:
- [System Architecture](docs/ARCHITECTURE.md)
- [REST & WebSocket API Reference](docs/API_REFERENCE.md)
- [Deployment Guide](docs/DEPLOYMENT_GUIDE.md)
- [Machine Learning Model Report](docs/ML_MODEL_REPORT.md)
- [SOC Analyst User Manual](docs/USER_MANUAL.md)
