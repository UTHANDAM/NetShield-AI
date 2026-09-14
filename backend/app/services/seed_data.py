"""
Seed Data Service — Populates database with:
  1. Default admin user
  2. Model training metrics (from Colab notebook output)
  3. Sample traffic records from both datasets
  4. Generated alerts from anomaly predictions
  5. Sample incidents, notifications, and threat indicators (Milestone 3)
"""
import os
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import AsyncSessionLocal
from app.models.user import (
    User, TrafficRecord, Alert, ModelMetric,
    Incident, IncidentNote, Notification, ThreatIndicator,
    DetectionRule, SoarAction
)
from app.middleware.auth import hash_password
from app.config import settings


async def seed_database():
    """Master seeding function — run on startup."""
    async with AsyncSessionLocal() as db:
        # Check if already seeded
        result = await db.execute(select(func.count(User.id)))
        user_count = result.scalar()
        if user_count > 0:
            print("[Seed] Database already populated. Checking detection rules...")
            rule_check = await db.execute(select(func.count(DetectionRule.id)))
            if rule_check.scalar() == 0:
                await seed_detection_rules(db)
                await seed_soar_actions(db)
                await db.commit()
            return

        print("[Seed] First run — populating database...")

        await seed_users(db)
        await seed_model_metrics(db)
        await seed_traffic_records(db)
        await seed_alerts(db)

        await db.commit()

        # Milestone 3 & 4 seeding (depends on alerts/users being committed)
        await seed_incidents(db)
        await seed_threat_indicators(db)
        await seed_notifications(db)
        await seed_detection_rules(db)
        await seed_soar_actions(db)

        await db.commit()
        print("[Seed] Database seeding complete!")


async def seed_users(db: AsyncSession):
    """Create default admin user."""
    admin = User(
        name="Admin",
        email="admin@netshield.ai",
        phone="+1-555-0100",
        password_hash=hash_password("admin123"),
        role="admin",
    )
    analyst = User(
        name="SOC Analyst",
        email="analyst@netshield.ai",
        phone="+1-555-0101",
        password_hash=hash_password("analyst123"),
        role="analyst",
    )
    viewer = User(
        name="Viewer",
        email="viewer@netshield.ai",
        phone="+1-555-0102",
        password_hash=hash_password("viewer123"),
        role="viewer",
    )
    db.add_all([admin, analyst, viewer])
    print("[Seed] Created 3 default users (admin/analyst/viewer)")


async def seed_model_metrics(db: AsyncSession):
    """Insert the actual training metrics from the Colab notebook output."""
    metrics = [
        # CICIDS2017 Binary Model
        ModelMetric(
            model_name="XGBoost Binary Classifier",
            dataset="cicids2017",
            model_type="binary",
            accuracy=0.9981,
            precision_score=0.9970,
            recall=0.9935,
            f1_score=0.9952,
            roc_auc=0.9988,
            fpr=0.0007,
            training_time_ms=910,
            confusion_matrix={"tn": 6804, "fp": 5, "fn": 11, "tp": 1667},
            per_class_metrics={
                "Normal": {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 6806},
                "Attack": {"precision": 1.00, "recall": 0.99, "f1": 1.00, "support": 1681},
            },
        ),
        # CICIDS2017 Multiclass Model
        ModelMetric(
            model_name="XGBoost Multiclass Classifier",
            dataset="cicids2017",
            model_type="multiclass",
            accuracy=0.9976,
            precision_score=0.9976,
            recall=0.9976,
            f1_score=0.9976,
            roc_auc=0.9990,
            training_time_ms=5210,
            per_class_metrics={
                "BENIGN": {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 6806},
                "DDoS": {"precision": 1.00, "recall": 0.99, "f1": 1.00, "support": 400},
                "DoS GoldenEye": {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 23},
                "DoS Hulk": {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 688},
                "DoS Slowhttptest": {"precision": 1.00, "recall": 0.94, "f1": 0.97, "support": 18},
                "DoS slowloris": {"precision": 0.95, "recall": 1.00, "f1": 0.97, "support": 18},
                "FTP-Patator": {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 29},
                "PortScan": {"precision": 0.99, "recall": 1.00, "f1": 1.00, "support": 474},
                "SSH-Patator": {"precision": 1.00, "recall": 1.00, "f1": 1.00, "support": 19},
            },
        ),
        # UNSW-NB15 Binary Model
        ModelMetric(
            model_name="XGBoost Binary Classifier",
            dataset="unsw_nb15",
            model_type="binary",
            accuracy=0.9059,
            precision_score=0.9854,
            recall=0.8745,
            f1_score=0.9267,
            roc_auc=0.9612,
            fpr=0.0274,
            training_time_ms=760,
            confusion_matrix={"tn": 2729, "fp": 77, "fn": 749, "tp": 5212},
            per_class_metrics={
                "Normal": {"precision": 0.78, "recall": 0.97, "f1": 0.87, "support": 2806},
                "Attack": {"precision": 0.99, "recall": 0.87, "f1": 0.93, "support": 5961},
            },
        ),
        # UNSW-NB15 Multiclass Model
        ModelMetric(
            model_name="XGBoost Multiclass Classifier",
            dataset="unsw_nb15",
            model_type="multiclass",
            accuracy=0.7500,
            precision_score=0.7500,
            recall=0.7500,
            f1_score=0.7200,
            roc_auc=0.8800,
            training_time_ms=2210,
            per_class_metrics={
                "normal": {"precision": 0.76, "recall": 0.98, "f1": 0.85, "support": 2806},
                "analysis": {"precision": 0.00, "recall": 0.00, "f1": 0.00, "support": 93},
                "backdoor": {"precision": 0.00, "recall": 0.00, "f1": 0.00, "support": 83},
                "dos": {"precision": 0.32, "recall": 0.47, "f1": 0.38, "support": 595},
                "exploits": {"precision": 0.71, "recall": 0.64, "f1": 0.67, "support": 1733},
                "fuzzers": {"precision": 0.69, "recall": 0.12, "f1": 0.20, "support": 879},
                "generic": {"precision": 0.97, "recall": 0.98, "f1": 0.98, "support": 1990},
                "reconnaissance": {"precision": 0.79, "recall": 0.75, "f1": 0.77, "support": 522},
                "shellcode": {"precision": 0.70, "recall": 0.25, "f1": 0.36, "support": 57},
                "worms": {"precision": 0.00, "recall": 0.00, "f1": 0.00, "support": 9},
            },
        ),
    ]

    db.add_all(metrics)
    print(f"[Seed] Inserted {len(metrics)} model metric records")


async def seed_traffic_records(db: AsyncSession):
    """Load a sample of real traffic records from both datasets."""
    sample_size = 500  # Records per dataset

    # --- CICIDS2017 ---
    cicids_dir = settings.CICIDS_PATH
    if os.path.exists(cicids_dir):
        try:
            csv_files = [f for f in os.listdir(cicids_dir) if f.endswith(".csv")]
            if csv_files:
                sample_file = os.path.join(cicids_dir, csv_files[0])
                df = pd.read_csv(sample_file, nrows=2000, encoding="utf-8", on_bad_lines="skip")
                df.columns = df.columns.str.strip()

                if len(df) > sample_size:
                    df = df.sample(n=sample_size, random_state=42)

                protocols = ["TCP", "UDP", "ICMP"]
                now = datetime.utcnow()

                for _, row in df.iterrows():
                    label_val = str(row.get("Label", "BENIGN")).strip()
                    attack_cat = label_val if label_val != "BENIGN" else None

                    record = TrafficRecord(
                        source_ip=f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                        dest_ip=f"10.0.{random.randint(0, 10)}.{random.randint(1, 254)}",
                        protocol=random.choice(protocols),
                        port=int(row.get("Destination Port", random.randint(20, 65535))),
                        duration=float(row.get("Flow Duration", 0)) if pd.notna(row.get("Flow Duration")) else 0,
                        packet_size=int(row.get("Total Length of Fwd Packets", 0)) if pd.notna(row.get("Total Length of Fwd Packets")) else 0,
                        label=label_val,
                        attack_cat=attack_cat,
                        dataset_source="cicids2017",
                        timestamp=now - timedelta(minutes=random.randint(0, 1440)),
                    )
                    db.add(record)

                print(f"[Seed] Loaded {min(len(df), sample_size)} CICIDS2017 traffic records")
        except Exception as e:
            print(f"[Seed] Error loading CICIDS2017: {e}")
    else:
        print(f"[Seed] CICIDS2017 path not found: {cicids_dir}")

    # --- UNSW-NB15 ---
    unsw_dir = settings.UNSW_PATH
    training_file = os.path.join(unsw_dir, "UNSW_NB15_training-set.csv")
    if os.path.exists(training_file):
        try:
            df = pd.read_csv(training_file, nrows=2000, encoding="utf-8", on_bad_lines="skip")
            df.columns = df.columns.str.strip()

            if len(df) > sample_size:
                df = df.sample(n=sample_size, random_state=42)

            protocols = ["tcp", "udp", "icmp"]
            now = datetime.utcnow()

            for _, row in df.iterrows():
                label_val = int(row.get("label", 0)) if pd.notna(row.get("label")) else 0
                attack_cat = str(row.get("attack_cat", "")).strip() if pd.notna(row.get("attack_cat")) else None
                if attack_cat and attack_cat.lower() in ("", "normal", "nan"):
                    attack_cat = None

                record = TrafficRecord(
                    source_ip=f"172.16.{random.randint(0, 254)}.{random.randint(1, 254)}",
                    dest_ip=f"10.1.{random.randint(0, 10)}.{random.randint(1, 254)}",
                    protocol=str(row.get("proto", random.choice(protocols))).lower(),
                    port=int(row.get("dsport", random.randint(20, 65535))) if pd.notna(row.get("dsport")) else random.randint(20, 65535),
                    duration=float(row.get("dur", 0)) if pd.notna(row.get("dur")) else 0,
                    packet_size=int(row.get("sbytes", 0)) if pd.notna(row.get("sbytes")) else 0,
                    label="Attack" if label_val == 1 else "Normal",
                    attack_cat=attack_cat,
                    dataset_source="unsw_nb15",
                    timestamp=now - timedelta(minutes=random.randint(0, 1440)),
                )
                db.add(record)

            print(f"[Seed] Loaded {min(len(df), sample_size)} UNSW-NB15 traffic records")
        except Exception as e:
            print(f"[Seed] Error loading UNSW-NB15: {e}")
    else:
        print(f"[Seed] UNSW-NB15 training file not found: {training_file}")


async def seed_alerts(db: AsyncSession):
    """Generate sample alerts with extended lifecycle statuses."""
    attacks = [
        {"attack_type": "DDoS", "severity": "CRITICAL", "risk_score": 92, "confidence": 0.97, "mitre": "T1498"},
        {"attack_type": "PortScan", "severity": "HIGH", "risk_score": 75, "confidence": 0.89, "mitre": "T1046"},
        {"attack_type": "DoS Hulk", "severity": "CRITICAL", "risk_score": 95, "confidence": 0.98, "mitre": "T1499"},
        {"attack_type": "FTP-Patator", "severity": "HIGH", "risk_score": 78, "confidence": 0.91, "mitre": "T1110"},
        {"attack_type": "SSH-Patator", "severity": "HIGH", "risk_score": 80, "confidence": 0.93, "mitre": "T1110"},
        {"attack_type": "Web Attack - Brute Force", "severity": "MEDIUM", "risk_score": 65, "confidence": 0.72, "mitre": "T1110"},
        {"attack_type": "DoS GoldenEye", "severity": "CRITICAL", "risk_score": 90, "confidence": 0.96, "mitre": "T1499"},
        {"attack_type": "Exploits", "severity": "CRITICAL", "risk_score": 88, "confidence": 0.94, "mitre": "T1203"},
        {"attack_type": "Generic", "severity": "MEDIUM", "risk_score": 55, "confidence": 0.68, "mitre": None},
        {"attack_type": "Reconnaissance", "severity": "HIGH", "risk_score": 72, "confidence": 0.85, "mitre": "T1595"},
        {"attack_type": "Fuzzers", "severity": "MEDIUM", "risk_score": 60, "confidence": 0.71, "mitre": "T1190"},
        {"attack_type": "DoS Slowhttptest", "severity": "HIGH", "risk_score": 82, "confidence": 0.91, "mitre": "T1499"},
        {"attack_type": "Backdoor", "severity": "CRITICAL", "risk_score": 95, "confidence": 0.97, "mitre": "T1059"},
        {"attack_type": "Shellcode", "severity": "CRITICAL", "risk_score": 93, "confidence": 0.96, "mitre": "T1059"},
        {"attack_type": "DoS slowloris", "severity": "HIGH", "risk_score": 79, "confidence": 0.88, "mitre": "T1499"},
    ]

    now = datetime.utcnow()
    statuses = ["new", "new", "new", "acknowledged", "investigating", "resolved", "closed"]
    analysts = ["Admin", "SOC Analyst", None, None]
    assets = ["Web Server 01", "DB Server", "Firewall", "API Gateway", "Mail Server", None]

    for i in range(60):
        attack = random.choice(attacks)
        status = random.choice(statuses)
        detected_at = now - timedelta(minutes=random.randint(0, 4320))

        ack_at = None
        res_at = None
        cls_at = None
        if status in ("acknowledged", "investigating", "escalated"):
            ack_at = detected_at + timedelta(minutes=random.randint(5, 120))
        if status == "resolved":
            ack_at = detected_at + timedelta(minutes=random.randint(5, 60))
            res_at = ack_at + timedelta(minutes=random.randint(30, 480))
        if status == "closed":
            ack_at = detected_at + timedelta(minutes=random.randint(5, 60))
            res_at = ack_at + timedelta(minutes=random.randint(30, 480))
            cls_at = res_at + timedelta(minutes=random.randint(10, 120))

        alert = Alert(
            source_ip=f"{random.choice(['192.168', '172.16', '10.0'])}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            dest_ip=f"10.0.{random.randint(0, 5)}.{random.randint(1, 254)}",
            protocol=random.choice(["TCP", "UDP", "ICMP"]),
            port=random.choice([22, 80, 443, 21, 8080, 3389, 445, 53]),
            attack_type=attack["attack_type"],
            risk_score=attack["risk_score"] + random.randint(-5, 5),
            severity=attack["severity"],
            confidence=round(attack["confidence"] + random.uniform(-0.05, 0.03), 4),
            dataset_source=random.choice(["cicids2017", "unsw_nb15"]),
            detected_at=detected_at,
            status=status,
            alert_type="network_anomaly",
            assigned_to=random.choice(analysts),
            mitre_technique=attack.get("mitre"),
            asset=random.choice(assets),
            acknowledged_at=ack_at,
            resolved_at=res_at,
            closed_at=cls_at,
        )
        db.add(alert)

    print("[Seed] Created 60 sample alert records")


async def seed_incidents(db: AsyncSession):
    """Create sample incidents linked to existing alerts."""
    now = datetime.utcnow()

    incidents_data = [
        {
            "title": "DDoS Attack on Web Infrastructure",
            "description": "Sustained volumetric DDoS attack targeting port 80/443 on web servers. Multiple source IPs identified from different ASNs.",
            "severity": "CRITICAL",
            "status": "investigation",
            "attack_category": "DDoS",
            "affected_assets": ["Web Server 01", "API Gateway", "Load Balancer"],
            "related_alert_ids": [1, 2, 3],
            "response_actions": [
                {"action": "Enabled rate limiting on WAF", "timestamp": (now - timedelta(hours=2)).isoformat(), "by": "Admin"},
                {"action": "Blocked top 5 attacking IPs at firewall", "timestamp": (now - timedelta(hours=1)).isoformat(), "by": "SOC Analyst"},
            ],
        },
        {
            "title": "SSH Brute Force Campaign",
            "description": "Coordinated SSH brute force attempts detected against multiple servers. Over 500 failed login attempts from 3 distinct IP ranges.",
            "severity": "HIGH",
            "status": "containment",
            "attack_category": "SSH-Patator",
            "affected_assets": ["DB Server", "Web Server 01"],
            "related_alert_ids": [4, 5],
            "response_actions": [
                {"action": "Disabled password auth, enforced key-based SSH", "timestamp": (now - timedelta(hours=3)).isoformat(), "by": "Admin"},
            ],
        },
        {
            "title": "Suspicious Port Scanning Activity",
            "description": "Sequential port scanning detected from external IP targeting internal network segments.",
            "severity": "MEDIUM",
            "status": "triage",
            "attack_category": "PortScan",
            "affected_assets": ["Firewall"],
            "related_alert_ids": [6, 7],
            "response_actions": [],
        },
        {
            "title": "Exploit Attempt on Web Application",
            "description": "Attempted exploitation of known vulnerability on public-facing web application. Payload matches CVE-2024-xxxx pattern.",
            "severity": "CRITICAL",
            "status": "resolution",
            "attack_category": "Exploits",
            "affected_assets": ["Web Server 01", "API Gateway"],
            "related_alert_ids": [8, 9, 10],
            "response_actions": [
                {"action": "Applied emergency patch", "timestamp": (now - timedelta(days=1)).isoformat(), "by": "Admin"},
                {"action": "Verified no data exfiltration", "timestamp": (now - timedelta(hours=12)).isoformat(), "by": "SOC Analyst"},
            ],
        },
        {
            "title": "Backdoor Detection on Mail Server",
            "description": "Suspected backdoor activity detected on mail server. Unusual outbound connections to known C2 infrastructure.",
            "severity": "CRITICAL",
            "status": "detection",
            "attack_category": "Backdoor",
            "affected_assets": ["Mail Server"],
            "related_alert_ids": [11, 12],
            "response_actions": [],
        },
    ]

    for inc_data in incidents_data:
        incident = Incident(
            title=inc_data["title"],
            description=inc_data["description"],
            severity=inc_data["severity"],
            status=inc_data["status"],
            assigned_analyst=random.choice(["Admin", "SOC Analyst"]),
            affected_assets=inc_data["affected_assets"],
            related_alert_ids=inc_data["related_alert_ids"],
            attack_category=inc_data["attack_category"],
            indicators=[],
            response_actions=inc_data["response_actions"],
            created_at=now - timedelta(hours=random.randint(2, 72)),
            closed_at=(now - timedelta(hours=1)) if inc_data["status"] in ("resolution", "closed") else None,
        )
        db.add(incident)
        await db.flush()

        # Add timeline notes
        note = IncidentNote(
            incident_id=incident.id,
            author="System",
            content=f"Incident auto-created from alert correlation. Category: {inc_data['attack_category']}.",
            note_type="timeline",
        )
        db.add(note)

        if inc_data["description"]:
            note2 = IncidentNote(
                incident_id=incident.id,
                author="SOC Analyst",
                content=f"Initial assessment: {inc_data['description']}",
                note_type="investigation",
            )
            db.add(note2)

        # Link alerts to incident
        for alert_id in inc_data["related_alert_ids"]:
            result = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if alert:
                alert.incident_id = incident.id

    print(f"[Seed] Created {len(incidents_data)} sample incidents with notes")


async def seed_threat_indicators(db: AsyncSession):
    """Create threat indicators derived from existing alert data."""
    now = datetime.utcnow()

    # Get unique source IPs from critical/high alerts
    result = await db.execute(
        select(Alert.source_ip, Alert.attack_type, Alert.severity, Alert.risk_score)
        .where(Alert.severity.in_(["CRITICAL", "HIGH"]))
        .distinct()
        .limit(15)
    )
    alert_ips = result.all()

    indicators = []
    for row in alert_ips:
        if row[0]:
            indicators.append(ThreatIndicator(
                indicator_type="ip",
                value=row[0],
                threat_category=row[1],
                severity=row[2],
                confidence=round(random.uniform(0.6, 0.98), 2),
                first_seen=now - timedelta(days=random.randint(1, 30)),
                last_seen=now - timedelta(hours=random.randint(0, 48)),
                source="internal",
                description=f"IP associated with {row[1]} attacks. Risk score: {row[3]}.",
                is_active=True,
            ))

    # Add some hash/domain indicators
    extra_indicators = [
        ThreatIndicator(
            indicator_type="hash",
            value="a1b2c3d4e5f6789012345678abcdef01",
            threat_category="Backdoor",
            severity="CRITICAL",
            confidence=0.95,
            first_seen=now - timedelta(days=5),
            last_seen=now - timedelta(hours=6),
            source="internal",
            description="MD5 hash of suspected backdoor payload detected on mail server.",
            is_active=True,
        ),
        ThreatIndicator(
            indicator_type="domain",
            value="malicious-c2-server.example.com",
            threat_category="Command and Control",
            severity="CRITICAL",
            confidence=0.92,
            first_seen=now - timedelta(days=3),
            last_seen=now - timedelta(hours=12),
            source="internal",
            description="Domain resolved by suspected backdoor for C2 communication.",
            is_active=True,
        ),
        ThreatIndicator(
            indicator_type="url",
            value="http://exploit-kit.example.net/payload.php",
            threat_category="Exploits",
            severity="HIGH",
            confidence=0.88,
            first_seen=now - timedelta(days=7),
            last_seen=now - timedelta(days=2),
            source="internal",
            description="URL serving exploit kit payload targeting web applications.",
            is_active=False,
        ),
        ThreatIndicator(
            indicator_type="malware",
            value="Trojan.GenericKD.46542",
            threat_category="Backdoor",
            severity="CRITICAL",
            confidence=0.97,
            first_seen=now - timedelta(days=2),
            last_seen=now - timedelta(hours=3),
            source="internal",
            description="Generic trojan signature detected in mail server memory dump.",
            is_active=True,
        ),
    ]
    indicators.extend(extra_indicators)

    db.add_all(indicators)
    print(f"[Seed] Created {len(indicators)} threat indicators")


async def seed_notifications(db: AsyncSession):
    """Create sample notifications for initial display."""
    now = datetime.utcnow()

    notifications = [
        Notification(
            title="CRITICAL Alert: DDoS Attack Detected",
            message="High-volume DDoS attack targeting Web Server 01. Immediate attention required.",
            severity="CRITICAL",
            notif_type="alert",
            related_id=1,
            related_type="alert",
            is_read=False,
            created_at=now - timedelta(minutes=15),
        ),
        Notification(
            title="New Incident Created: SSH Brute Force Campaign",
            message="Incident #2 created from correlated SSH brute force alerts. Assigned to SOC Analyst.",
            severity="HIGH",
            notif_type="incident",
            related_id=2,
            related_type="incident",
            is_read=False,
            created_at=now - timedelta(minutes=45),
        ),
        Notification(
            title="Incident Status Update: DDoS Attack",
            message="Incident #1 moved to 'Investigation' phase. Rate limiting has been applied.",
            severity="HIGH",
            notif_type="incident",
            related_id=1,
            related_type="incident",
            is_read=True,
            created_at=now - timedelta(hours=2),
        ),
        Notification(
            title="HIGH Alert: Port Scanning Activity",
            message="Sequential port scanning detected from 172.16.45.23 targeting internal network.",
            severity="HIGH",
            notif_type="alert",
            related_id=6,
            related_type="alert",
            is_read=False,
            created_at=now - timedelta(hours=3),
        ),
        Notification(
            title="Incident Resolved: Exploit Attempt",
            message="Incident #4 resolved. Emergency patch applied and no data exfiltration confirmed.",
            severity="MEDIUM",
            notif_type="incident",
            related_id=4,
            related_type="incident",
            is_read=True,
            created_at=now - timedelta(hours=12),
        ),
        Notification(
            title="CRITICAL Alert: Backdoor Detected",
            message="Suspected backdoor activity on Mail Server. Unusual outbound C2 connections.",
            severity="CRITICAL",
            notif_type="alert",
            related_id=11,
            related_type="alert",
            is_read=False,
            created_at=now - timedelta(minutes=30),
        ),
        Notification(
            title="System: New Threat Indicators Added",
            message="15 new threat indicators extracted from recent alert analysis and added to the intelligence database.",
            severity="INFO",
            notif_type="system",
            is_read=True,
            created_at=now - timedelta(hours=6),
        ),
    ]

    db.add_all(notifications)
    print(f"[Seed] Created {len(notifications)} sample notifications")


async def seed_detection_rules(db: AsyncSession):
    """Create default detection rules for SIEM/NIDS engines."""
    rules = [
        DetectionRule(
            name="SQL Injection Attempt",
            engine_type="Suricata",
            description="Detects classic SQL injection UNION SELECT and SQL comment injections targeting web servers.",
            pattern='alert tcp any any -> any $HTTP_PORTS (msg:"NETSHIELD SQL Injection Attack"; flow:to_server,established; content:"UNION"; nocase; content:"SELECT"; nocase; sid:100001; rev:1;)',
            severity="CRITICAL",
            is_enabled=True,
            hit_count=124,
        ),
        DetectionRule(
            name="Large ICMP Ping Flood",
            engine_type="Zeek",
            description="Identifies ICMP ping flood denial of service attempts exceeding 500 packets/second.",
            pattern='event icmp_echo_request(c: connection, info: icmp_info) { if (Site::is_local_host(c$id$resp_h) && current_time() - last_icmp < 0.002sec) { NOTICE(...); } }',
            severity="HIGH",
            is_enabled=True,
            hit_count=89,
        ),
        DetectionRule(
            name="Suspicious SSH Login Burst",
            engine_type="YARA",
            description="YARA rule parsing auth.log for brute-force password guessing patterns.",
            pattern='rule Suspicious_SSH_Brute_Force { meta: author = "NetShield SOC" threat = "Brute Force" strings: $fail = "Failed password for" condition: #fail in (0..filesize) > 10 }',
            severity="MEDIUM",
            is_enabled=True,
            hit_count=34,
        ),
        DetectionRule(
            name="Ransomware C2 Beaconing",
            engine_type="Suricata",
            description="Detects regular outbound encrypted heartbeat beacons to known command & control nodes.",
            pattern='alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"NETSHIELD Ransomware C2 Beacon"; flow:established; threshold:type both, track by_src, count 10, seconds 60; sid:100004;)',
            severity="CRITICAL",
            is_enabled=True,
            hit_count=7,
        ),
        DetectionRule(
            name="Nmap Xmas / Null Port Scan",
            engine_type="Zeek",
            description="Triggers on TCP packets with invalid flag combinations (FIN-PSH-URG or zero flags).",
            pattern='event tcp_packet(c: connection, is_orig: bool, flags: string) { if (flags == "FPU" || flags == "") { NOTICE(...); } }',
            severity="MEDIUM",
            is_enabled=True,
            hit_count=512,
        ),
        DetectionRule(
            name="AI ML Deep Outlier Anomaly",
            engine_type="Custom AI",
            description="Statistical isolation forest boundary deviation coupled with multi-class threat probability > 0.85.",
            pattern='IsolationForest.anomaly_score < -0.35 AND XGBoost.threat_prob > 0.85',
            severity="HIGH",
            is_enabled=True,
            hit_count=98,
        ),
    ]

    db.add_all(rules)
    print(f"[Seed] Created {len(rules)} detection rules")


async def seed_soar_actions(db: AsyncSession):
    """Create sample SOAR playbook actions and execution history."""
    now = datetime.utcnow()
    actions = [
        SoarAction(
            action_type="block_ip",
            target="192.168.1.105",
            incident_id=1,
            executed_by="SOC Analyst",
            status="SUCCESS",
            result_summary="IP 192.168.1.105 added to perimeter firewall drop rule. IPTables policy updated across all edge gateways.",
            parameters={"firewall": "Edge-FW-01", "duration": "24h", "action": "DROP"},
            created_at=now - timedelta(hours=2),
        ),
        SoarAction(
            action_type="isolate_host",
            target="10.0.0.15 (Web Server 01)",
            incident_id=1,
            executed_by="SOC Analyst",
            status="SUCCESS",
            result_summary="Switch port GigabitEthernet1/0/12 assigned to Quarantine VLAN 999. Ingress and egress traffic blocked except for SOC telemetry.",
            parameters={"vlan": 999, "switch": "SW-CORE-01"},
            created_at=now - timedelta(hours=1, minutes=45),
        ),
        SoarAction(
            action_type="revoke_session",
            target="admin@corporate.corp",
            incident_id=2,
            executed_by="Admin",
            status="SUCCESS",
            result_summary="Active OAuth2 and JWT bearer tokens immediately invalidated in Redis cache. Forced multi-factor re-authentication required.",
            parameters={"user_email": "admin@corporate.corp", "revoke_refresh": True},
            created_at=now - timedelta(minutes=40),
        ),
        SoarAction(
            action_type="rate_limit",
            target="TCP Port 80/443 (Reverse Proxy)",
            incident_id=3,
            executed_by="SOC System",
            status="SUCCESS",
            result_summary="Enforced token-bucket rate limit of 100 req/sec per source IP across Nginx ingress controllers.",
            parameters={"rate": "100r/s", "burst": 50},
            created_at=now - timedelta(minutes=20),
        ),
    ]

    db.add_all(actions)
    print(f"[Seed] Created {len(actions)} SOAR playbook action logs")

