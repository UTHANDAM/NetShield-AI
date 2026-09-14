# NetShield AI — REST & WebSocket API Reference

The NetShield AI Backend exposes a high-performance RESTful API and real-time WebSocket stream built on FastAPI.

**Base URL**: `http://localhost:8000/api`  
**Interactive Swagger UI**: `http://localhost:8000/docs`  
**ReDoc Specification**: `http://localhost:8000/redoc`

---

## 1. Authentication (`/api/auth`)

### `POST /api/auth/token`
Authenticates a user and returns a JWT Bearer token.
- **Request (OAuth2 Form / JSON)**:
  ```json
  {
    "username": "admin@netshield.ai",
    "password": "Admin@123456"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1Ni...",
    "token_type": "bearer",
    "user": {
      "id": 1,
      "email": "admin@netshield.ai",
      "full_name": "SOC Administrator",
      "role": "admin"
    }
  }
  ```

### `GET /api/auth/me`
Retrieves profile and role information for the currently authenticated user.
- **Headers**: `Authorization: Bearer <token>`
- **Response `200 OK`**: User profile object.

---

## 2. Traffic Telemetry (`/api/traffic`)

### `GET /api/traffic/live`
Fetches the latest paginated network flow records with optional anomaly filtering.
- **Query Parameters**:
  - `limit` (int, default: 50): Number of records.
  - `anomalous_only` (bool, default: false): Filter strictly anomalous flows.
- **Response `200 OK`**: List of flow records.

### `WS /api/traffic/ws`
Real-time WebSocket connection streaming live network packets, flow metrics, and alert scores.
- **Payload Format**:
  ```json
  {
    "id": 1024,
    "timestamp": "2026-09-10T11:45:00Z",
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.1",
    "src_port": 49210,
    "dst_port": 80,
    "protocol": "TCP",
    "packet_length": 1420,
    "is_anomaly": true,
    "threat_type": "DDoS",
    "severity": "CRITICAL",
    "anomaly_score": 0.984
  }
  ```

### `POST /api/traffic/simulate-attack`
Injects simulated attack traffic bursts into the live telemetry feed for SOC training and testing.
- **Request**:
  ```json
  {
    "attack_type": "DDoS", // DDoS | SYN_FLOOD | SSH_SPRAY | SQL_INJECTION
    "packet_count": 50,
    "intensity": "high"
  }
  ```
- **Response `200 OK`**: `{ "status": "simulated", "packets_injected": 50, "alert_triggered": true }`

---

## 3. Threat Alerts (`/api/alerts`)

### `GET /api/alerts`
Lists security alerts with filtering by severity, status, and time range.
- **Query Parameters**: `severity`, `status`, `limit`, `offset`
- **Response `200 OK`**: Paginated alert objects.

### `PATCH /api/alerts/{id}`
Updates alert disposition status (`OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).

---

## 4. Incident Management & SOAR (`/api/incidents`)

### `GET /api/incidents`
Lists correlated security incidents, incident MTTR, and SLA tracking.

### `GET /api/incidents/{id}`
Fetches incident details, linked alerts, affected assets, and historical timeline logs.

### `POST /api/incidents/{id}/notes`
Adds an analyst investigation note to the incident timeline.

### `POST /api/incidents/{id}/soar`
Executes an automated SOAR remediation playbook against the incident.
- **Request**:
  ```json
  {
    "action": "block_ip", // block_ip | isolate_host | rate_limit | revoke_session | forensics
    "target_ip": "198.51.100.42",
    "reason": "Automated containment of malicious C2 communication"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "success": true,
    "action": "block_ip",
    "target_ip": "198.51.100.42",
    "timestamp": "2026-09-10T11:45:00Z",
    "execution_time_ms": 42.5,
    "audit_id": 84,
    "output": "IP 198.51.100.42 successfully blocked in perimeter firewall and added to dynamic blocklist."
  }
  ```

---

## 5. Threat Intelligence & Rules (`/api/threat-intel`)

### `GET /api/threat-intel/mitre-matrix`
Returns the 14 MITRE ATT&CK enterprise tactics and mapped detection rules/alerts with active threat counts.

### `GET /api/threat-intel/iocs`
Lists Indicators of Compromise (IPs, domains, hashes, CVEs) with reputation scores.

### `GET /api/threat-intel/detection-rules`
Lists active SIEM / NIDS detection rules.

### `POST /api/threat-intel/detection-rules`
Creates a new signature or heuristic detection rule.
- **Request**:
  ```json
  {
    "name": "Outbound Cobalt Strike Beacon",
    "severity": "CRITICAL",
    "category": "Command and Control",
    "rule_logic": "flow.dst_port == 443 && flow.payload_entropy > 7.2 && flow.interval_jitter < 0.05",
    "mitre_id": "T1071.001",
    "is_active": true
  }
  ```

---

## 6. Machine Learning Models (`/api/ml`)

### `GET /api/ml/metrics`
Returns performance evaluation metrics (Accuracy, Precision, Recall, F1-Score, ROC-AUC) for all 4 loaded models.

### `POST /api/ml/predict`
Runs live inference on a custom feature vector through CIC-IDS-2017 or UNSW-NB15 pipelines.
- **Request**:
  ```json
  {
    "dataset": "cicids", // cicids | unswnb15
    "model_type": "xgboost",
    "features": {
      "Destination Port": 80,
      "Flow Duration": 120500,
      "Total Fwd Packets": 45,
      "Total Backward Packets": 38,
      "Flow Bytes/s": 450200.5
    }
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "dataset": "cicids",
    "is_anomaly": true,
    "predicted_class": "DDoS",
    "confidence_score": 0.992,
    "inference_time_ms": 1.2
  }
  ```

---

## 7. Forensic Reports (`/api/reports`)

### `GET /api/reports/generate/pdf`
Generates and downloads a branded SOC Executive & Forensic PDF report containing executive summary, KPI dashboard, incident timeline, MITRE ATT&CK coverage, and SOAR audit trail.

### `GET /api/reports/export/csv`
Exports telemetry or incident logs in standard CSV format for SIEM ingestion.
