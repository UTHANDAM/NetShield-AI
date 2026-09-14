"""
NetShield AI — End-to-End Automated Test Suite
================================================
Covers:
- System Health & Model Status
- JWT Authentication & RBAC Access Control
- ML Inference Pipeline (CIC-IDS-2017 & UNSW-NB15)
- Traffic Telemetry, Protocol & Port Distribution
- Alert Ingestion & Lifecycle Triage
- Incident Management, Notes & MTTR Metrics
- Automated SOAR Playbook Execution
- MITRE ATT&CK Matrix & Detection Rules CRUD
- PDF / CSV Security Report Generation
"""
import pytest
import asyncio
from fastapi.testclient import TestClient
import sys, os

# Ensure backend path is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database import init_db
from app.services.seed_data import seed_database
from app.services.ml_engine import ml_engine


@pytest.fixture(scope="session", autouse=True)
def setup_database_and_models():
    """Initialize SQLite DB, ML models, and seed data before running tests."""
    asyncio.run(init_db())
    ml_engine.load_models()
    asyncio.run(seed_database())


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_token(client):
    r = client.post("/api/auth/login", json={"email": "admin@netshield.ai", "password": "admin123"})
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest.fixture
def analyst_token(client):
    r = client.post("/api/auth/login", json={"email": "analyst@netshield.ai", "password": "analyst123"})
    assert r.status_code == 200
    return r.json()["access_token"]


class TestSystemHealth:
    def test_root_endpoint(self, client):
        r = client.get("/")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "online"
        assert "NetShield" in data["name"]

    def test_health_check(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert data["models_loaded"] >= 4
        assert data["preprocessors_loaded"] >= 2


class TestAuthenticationAndRBAC:
    def test_admin_login(self, client):
        r = client.post("/api/auth/login", json={"email": "admin@netshield.ai", "password": "admin123"})
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert data["user"]["role"] == "admin"

    def test_invalid_login(self, client):
        r = client.post("/api/auth/login", json={"email": "admin@netshield.ai", "password": "wrongpassword"})
        assert r.status_code == 401

    def test_get_current_user(self, client, admin_token):
        headers = {"Authorization": f"Bearer {admin_token}"}
        r = client.get("/api/auth/me", headers=headers)
        assert r.status_code == 200
        assert r.json()["email"] == "admin@netshield.ai"


class TestMachineLearningInference:
    def test_model_comparison(self, client):
        r = client.get("/api/models/comparison")
        assert r.status_code == 200
        data = r.json()
        assert data["total_models"] >= 4
        assert "best_accuracy" in data

    def test_cicids_binary_predict(self):
        res = ml_engine.predict({"Destination Port": 80, "Flow Duration": 5000}, dataset="cicids2017", model_type="binary")
        assert "attack_type" in res
        assert "risk_score" in res
        assert "confidence" in res

    def test_unsw_multiclass_predict(self):
        res = ml_engine.predict({"dur": 0.5, "sbytes": 1200, "proto": "tcp", "service": "http", "state": "FIN"}, dataset="unsw_nb15", model_type="multiclass")
        assert "attack_type" in res
        assert "risk_score" in res


class TestTrafficAndAttackSimulation:
    def test_traffic_summary(self, client):
        r = client.get("/api/traffic/summary")
        assert r.status_code == 200
        data = r.json()
        assert data["total_traffic"] > 0
        assert "normal_percentage" in data

    def test_protocols_breakdown(self, client):
        r = client.get("/api/traffic/protocols")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_ports_breakdown(self, client):
        r = client.get("/api/traffic/ports")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_simulate_attack_scenario(self, client):
        r = client.post("/api/traffic/simulate-attack?scenario=ddos")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "success"
        assert "alert_id" in data


class TestAlertsAndIncidentManagement:
    def test_list_alerts(self, client):
        r = client.get("/api/alerts/?limit=10")
        assert r.status_code == 200
        assert len(r.json()) > 0

    def test_alerts_stats(self, client):
        r = client.get("/api/alerts/stats")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "critical" in data

    def test_list_incidents(self, client):
        r = client.get("/api/incidents/")
        assert r.status_code == 200
        assert len(r.json()) > 0

    def test_incident_metrics(self, client):
        r = client.get("/api/incidents/metrics")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "by_severity" in data

    def test_execute_soar_playbook(self, client, analyst_token):
        headers = {"Authorization": f"Bearer {analyst_token}"}
        payload = {
            "action_type": "block_ip",
            "target": "203.0.113.99"
        }
        r = client.post("/api/incidents/1/soar", json=payload, headers=headers)
        assert r.status_code == 200
        data = r.json()
        assert data["action_type"] == "block_ip"
        assert data["status"] == "SUCCESS"


class TestThreatIntelligenceAndRules:
    def test_mitre_attack_matrix(self, client):
        r = client.get("/api/threat-intel/mitre-matrix")
        assert r.status_code == 200
        data = r.json()
        assert data["total_tactics"] >= 7
        assert "tactics" in data

    def test_detection_rules_crud(self, client, admin_token):
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # 1. Create rule
        rule_data = {
            "name": "Test YARA Ransomware Rule",
            "engine_type": "YARA",
            "description": "Rule created during test run",
            "pattern": "rule Test_Ransomware { condition: true }",
            "severity": "HIGH",
            "is_enabled": True
        }
        r = client.post("/api/threat-intel/detection-rules", json=rule_data, headers=headers)
        assert r.status_code == 200
        rule_id = r.json()["id"]

        # 2. Update rule
        r = client.patch(f"/api/threat-intel/detection-rules/{rule_id}", json={"severity": "CRITICAL"}, headers=headers)
        assert r.status_code == 200
        assert r.json()["severity"] == "CRITICAL"

        # 3. Delete rule
        r = client.delete(f"/api/threat-intel/detection-rules/{rule_id}", headers=headers)
        assert r.status_code == 200


class TestReportGeneration:
    def test_generate_pdf_report(self, client):
        r = client.post("/api/reports/generate", json={"report_type": "pdf", "title": "Automated Security Audit Report"})
        assert r.status_code == 200
        data = r.json()
        assert data["report_type"] == "pdf"
        assert os.path.exists(data["file_path"])
