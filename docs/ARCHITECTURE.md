# NetShield AI — System Architecture & Technical Specification

## 1. System Overview
**NetShield AI** is an enterprise-grade Security Operations Center (SOC) platform designed for real-time network anomaly detection, automated incident triage, threat intelligence correlation, and SOAR (Security Orchestration, Automation, and Response) remediation.

NetShield AI leverages dual machine learning models trained on **CIC-IDS-2017** and **UNSW-NB15** alongside deep feature extraction, signature-based SIEM detection rules, MITRE ATT&CK matrix mapping, and live WebSocket telemetry feeds.

```mermaid
graph TD
    subgraph Ingestion & Telemetry Layer
        NIC[Network Interface / PCAP] --> FlowExtractor[Flow & Feature Extractor]
        TrafficSim[Attack Simulator] --> FlowExtractor
        FlowExtractor --> FeatureNorm[Feature Normalizer & Scaler]
    end

    subgraph AI / ML Detection Engine
        FeatureNorm --> CIC_Binary[CIC-IDS-2017 Binary Classifier]
        FeatureNorm --> CIC_Multi[CIC-IDS-2017 Multiclass Classifier]
        FeatureNorm --> UNSW_Binary[UNSW-NB15 Binary Classifier]
        FeatureNorm --> UNSW_Multi[UNSW-NB15 Multiclass Classifier]
        CIC_Binary & CIC_Multi & UNSW_Binary & UNSW_Multi --> AnomalyScorer[Anomaly Scorer & Correlation Engine]
    end

    subgraph Core Backend Services (FastAPI 0.115)
        AnomalyScorer --> AlertManager[Alert & Correlation Service]
        RuleEngine[SIEM Detection Rule Engine] --> AlertManager
        AlertManager --> IncidentTracker[Incident Lifecycle & Timeline Tracker]
        IncidentTracker --> SOARPlaybooks[SOAR Automation Playbooks]
        AlertManager --> WSBroadcaster[WebSocket Broadcaster]
        AlertManager --> SQLiteDB[(SQLAlchemy Async / SQLite / Postgres)]
    end

    subgraph Frontend SOC Dashboard (Next.js 14 + Tailwind CSS)
        WSBroadcaster --> LiveMonitor[Live Traffic & Threat Console]
        SQLiteDB --> RestAPI[REST API Client]
        RestAPI --> DashboardUI[Dashboard KPIs & Metrics]
        RestAPI --> IncidentConsole[Incident Management & SOAR Trigger]
        RestAPI --> ThreatIntel[Threat Intelligence & MITRE Matrix]
        RestAPI --> MLInspector[AI Model Performance & ROC Visualizer]
        RestAPI --> PDFGenerator[ReportLab SOC PDF & CSV Exporter]
    end
```

---

## 2. Component Breakdown

### 2.1 Dual ML Detection Architecture
NetShield AI operates a dual-dataset model architecture with fallback and multi-model consensus:
- **CIC-IDS-2017 Pipeline**:
  - Binary classifier (`XGBClassifier` / `RandomForest`): Detects normal vs. anomalous network flows with >99% ROC-AUC.
  - Multiclass classifier (`XGBClassifier`): Categorizes 14 distinct attack classes including `DDoS`, `PortScan`, `Botnet`, `BruteForce`, `Infiltration`, `Heartbleed`, and `Web Attacks`.
  - Feature Vector: 70 continuous statistical features scaled using `StandardScaler`.
- **UNSW-NB15 Pipeline**:
  - Binary classifier (`XGBClassifier` / `RandomForest`): Robust detection against modern evasion techniques.
  - Multiclass classifier (`XGBClassifier`): Classifies 10 attack categories (`Fuzzers`, `Analysis`, `Backdoors`, `DoS`, `Exploits`, `Generic`, `Reconnaissance`, `Shellcode`, `Worms`).
  - Feature Vector: 42 features including categorical protocol mappings (`proto`, `service`, `state`) transformed via `LabelEncoder`.

### 2.2 Telemetry Ingestion & WebSocket Stream
- **Live Stream Endpoint**: `ws://localhost:8000/api/traffic/ws`
- Broadcasts real-time network flow packets with IP headers, flow metrics, anomaly flags, and severity scores at configurable frequencies (default: 1 packet/sec).
- Supports live attack injection (`POST /api/traffic/simulate-attack`) allowing SOC analysts to simulate active DDoS, SYN Port Scans, SSH Password Spray, and SQL Injection attacks on demand.

### 2.3 Incident Management & Automated SOAR Engine
- **Correlation Engine**: Aggregates raw alerts matching identical source IPs, destination IPs, or attack signatures into unified, manageable Security Incidents.
- **SOAR Automated Playbooks**:
  1. `block_ip`: Generates firewall rules (iptables/Windows Firewall) and blacklists threat IP in IOC database.
  2. `isolate_host`: Disconnects compromised host from network segment via VLAN quarantine.
  3. `rate_limit`: Implements QoS traffic shaping and token bucket rate limiting on targeted ports.
  4. `revoke_session`: Invalidates active JWT authentication tokens and terminates compromised user sessions.
  5. `run_full_forensics`: Executes memory capture, packet capture dump, and triggers automated forensic PDF generation.

### 2.4 Data Layer & ORM
- **Database Engine**: SQLAlchemy 2.0 with `asyncio` and `aiosqlite`.
- **Entities**:
  - `User`: RBAC authentication (Admin, Analyst, Viewer).
  - `TrafficRecord`: High-throughput network flow records.
  - `Alert`: Triggered security alerts with severity and confidence metrics.
  - `Incident` & `IncidentNote`: Correlated threat incidents with historical timeline logs.
  - `ThreatIndicator`: IOC database containing IP, domain, hash, and CVE threat intelligence.
  - `DetectionRule`: SIEM/NIDS detection rules with YAML/Suricata-compatible syntax.
  - `SoarAction`: Immutable audit log of all automated and manual SOAR playbook executions.
  - `Report`: Generated executive summary and forensic technical reports.

---

## 3. Security & Compliance
- **Authentication**: Stateless JSON Web Tokens (JWT) signed with HMAC-SHA256.
- **Password Hashing**: Direct `bcrypt` key derivation with automated salt generation.
- **Authorization**: Role-Based Access Control (RBAC) enforced via FastAPI dependency injection:
  - `admin`: Full administrative access, user management, rule modifications, SOAR execution.
  - `analyst`: Incident triage, note creation, alert dispositioning, report generation.
  - `viewer`: Read-only access to dashboard telemetry and public reports.
- **CORS & Headers**: Strict CORS origin validation, content security headers, and rate-limiting middleware.
