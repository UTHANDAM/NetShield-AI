"""Traffic router — Traffic records, stats, and summary endpoints."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, desc
from typing import Optional
from app.database import get_db
from app.models.user import TrafficRecord, Alert
from app.models.schemas import TrafficRecordResponse, TrafficStats, TrafficSummary

router = APIRouter(prefix="/api/traffic", tags=["Traffic"])


@router.get("/records")
async def get_traffic_records(
    dataset: Optional[str] = None,
    label: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """Get paginated traffic records with optional filtering."""
    query = select(TrafficRecord).order_by(desc(TrafficRecord.timestamp))
    if dataset:
        query = query.where(TrafficRecord.dataset_source == dataset)
    if label:
        query = query.where(TrafficRecord.label == label)
    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    records = result.scalars().all()
    return [TrafficRecordResponse.model_validate(r) for r in records]


@router.get("/stats", response_model=TrafficStats)
async def get_traffic_stats(
    dataset: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get aggregated traffic statistics."""
    base = select(TrafficRecord)
    if dataset:
        base = base.where(TrafficRecord.dataset_source == dataset)

    # Total count
    total_q = select(func.count(TrafficRecord.id))
    if dataset:
        total_q = total_q.where(TrafficRecord.dataset_source == dataset)
    total = (await db.execute(total_q)).scalar() or 0

    # Attack vs Normal counts
    attack_q = select(func.count(TrafficRecord.id)).where(
        TrafficRecord.label.notin_(["BENIGN", "Normal", "normal"])
    )
    if dataset:
        attack_q = attack_q.where(TrafficRecord.dataset_source == dataset)
    attack_count = (await db.execute(attack_q)).scalar() or 0
    normal_count = total - attack_count

    # Protocol distribution
    proto_q = select(TrafficRecord.protocol, func.count(TrafficRecord.id)).group_by(TrafficRecord.protocol)
    if dataset:
        proto_q = proto_q.where(TrafficRecord.dataset_source == dataset)
    proto_result = await db.execute(proto_q)
    protocol_distribution = {str(row[0] or "Unknown"): row[1] for row in proto_result.all()}

    # Top source IPs
    src_q = (
        select(TrafficRecord.source_ip, func.count(TrafficRecord.id).label("count"))
        .group_by(TrafficRecord.source_ip)
        .order_by(desc("count"))
        .limit(10)
    )
    if dataset:
        src_q = src_q.where(TrafficRecord.dataset_source == dataset)
    src_result = await db.execute(src_q)
    top_source_ips = [{"ip": row[0], "count": row[1]} for row in src_result.all()]

    # Top dest IPs
    dst_q = (
        select(TrafficRecord.dest_ip, func.count(TrafficRecord.id).label("count"))
        .group_by(TrafficRecord.dest_ip)
        .order_by(desc("count"))
        .limit(10)
    )
    if dataset:
        dst_q = dst_q.where(TrafficRecord.dataset_source == dataset)
    dst_result = await db.execute(dst_q)
    top_dest_ips = [{"ip": row[0], "count": row[1]} for row in dst_result.all()]

    # Attack distribution
    atk_q = (
        select(TrafficRecord.attack_cat, func.count(TrafficRecord.id))
        .where(TrafficRecord.attack_cat.isnot(None))
        .group_by(TrafficRecord.attack_cat)
    )
    if dataset:
        atk_q = atk_q.where(TrafficRecord.dataset_source == dataset)
    atk_result = await db.execute(atk_q)
    attack_distribution = {str(row[0]): row[1] for row in atk_result.all()}

    return TrafficStats(
        total_records=total,
        attack_count=attack_count,
        normal_count=normal_count,
        protocol_distribution=protocol_distribution,
        top_source_ips=top_source_ips,
        top_dest_ips=top_dest_ips,
        attack_distribution=attack_distribution,
    )


@router.get("/summary", response_model=TrafficSummary)
async def get_traffic_summary(db: AsyncSession = Depends(get_db)):
    """Dashboard summary widget data."""
    total = (await db.execute(select(func.count(TrafficRecord.id)))).scalar() or 0

    attack_q = select(func.count(TrafficRecord.id)).where(
        TrafficRecord.label.notin_(["BENIGN", "Normal", "normal"])
    )
    threats = (await db.execute(attack_q)).scalar() or 0

    active_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == "open")
    )).scalar() or 0

    # Aggregate risk score from open alerts
    avg_risk = (await db.execute(
        select(func.avg(Alert.risk_score)).where(Alert.status == "open")
    )).scalar() or 0

    # Which datasets are loaded
    datasets = (await db.execute(
        select(TrafficRecord.dataset_source).distinct()
    )).scalars().all()

    normal_pct = round((total - threats) / max(total, 1) * 100, 1)
    attack_pct = round(threats / max(total, 1) * 100, 1)

    return TrafficSummary(
        total_traffic=total,
        threats_detected=threats,
        active_alerts=active_alerts,
        risk_score=int(avg_risk),
        datasets_loaded=list(datasets),
        normal_percentage=normal_pct,
        attack_percentage=attack_pct,
    )


@router.get("/protocols")
async def get_protocol_stats(db: AsyncSession = Depends(get_db)):
    """Protocol distribution for telemetry charts."""
    proto_q = select(TrafficRecord.protocol, func.count(TrafficRecord.id)).group_by(TrafficRecord.protocol)
    proto_result = await db.execute(proto_q)
    return [{"name": str(row[0] or "Unknown"), "value": row[1]} for row in proto_result.all()]


@router.get("/ports")
async def get_port_usage(db: AsyncSession = Depends(get_db)):
    """Port distribution for network security analysis."""
    port_q = (
        select(TrafficRecord.port, func.count(TrafficRecord.id).label("count"))
        .where(TrafficRecord.port.isnot(None))
        .group_by(TrafficRecord.port)
        .order_by(desc("count"))
        .limit(10)
    )
    port_result = await db.execute(port_q)
    port_names = {
        80: "HTTP (80)", 443: "HTTPS (443)", 22: "SSH (22)", 21: "FTP (21)",
        53: "DNS (53)", 3389: "RDP (3389)", 8080: "HTTP-Alt (8080)", 25: "SMTP (25)"
    }
    return [
        {"port": row[0], "name": port_names.get(row[0], f"Port {row[0]}"), "count": row[1]}
        for row in port_result.all()
    ]


# ── Live Traffic Simulation & Attack Ingestion ──────────────────────────────
import asyncio
import random
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect
from app.services.ml_engine import ml_engine
from app.database import AsyncSessionLocal

_attack_queue = asyncio.Queue()

ATTACK_SCENARIOS = {
    "ddos": {
        "title": "DDoS HTTP Layer 7 Flood",
        "attack_type": "DDoS",
        "severity": "CRITICAL",
        "source_ips": ["185.220.101.5", "185.220.101.6", "185.220.101.7"],
        "dest_ip": "10.0.0.15",
        "port": 80,
        "protocol": "TCP",
        "risk_score": 98,
        "confidence": 0.995,
        "mitre": "T1498 (Network Denial of Service)",
    },
    "port_scan": {
        "title": "SYN Stealth Reconnaissance Scan",
        "attack_type": "PortScan",
        "severity": "HIGH",
        "source_ips": ["172.16.45.23"],
        "dest_ip": "10.0.0.20",
        "port": 445,
        "protocol": "TCP",
        "risk_score": 82,
        "confidence": 0.965,
        "mitre": "T1046 (Network Service Discovery)",
    },
    "brute_force": {
        "title": "SSH Credential Spraying Attack",
        "attack_type": "SSH-Patator",
        "severity": "HIGH",
        "source_ips": ["198.51.100.44"],
        "dest_ip": "10.0.0.50",
        "port": 22,
        "protocol": "TCP",
        "risk_score": 78,
        "confidence": 0.942,
        "mitre": "T1110 (Brute Force)",
    },
    "sql_injection": {
        "title": "Web Application SQL Injection",
        "attack_type": "Web Attack - Brute Force",
        "severity": "CRITICAL",
        "source_ips": ["203.0.113.88"],
        "dest_ip": "10.0.0.15",
        "port": 443,
        "protocol": "TCP",
        "risk_score": 94,
        "confidence": 0.988,
        "mitre": "T1190 (Exploit Public-Facing Application)",
    },
    "c2_beacon": {
        "title": "Ransomware Command & Control Beacon",
        "attack_type": "Bot",
        "severity": "CRITICAL",
        "source_ips": ["10.0.0.35"],
        "dest_ip": "194.26.29.112",
        "port": 443,
        "protocol": "TCP",
        "risk_score": 96,
        "confidence": 0.991,
        "mitre": "T1071 (Application Layer Protocol: C2)",
    },
}


@router.post("/simulate-attack")
async def trigger_attack_simulation(scenario: str = "ddos", db: AsyncSession = Depends(get_db)):
    """Inject a live attack scenario to demonstrate real-time SOC alerting & response."""
    scenario_info = ATTACK_SCENARIOS.get(scenario.lower(), ATTACK_SCENARIOS["ddos"])
    src_ip = random.choice(scenario_info["source_ips"])
    
    # 1. Create Alert in DB
    alert = Alert(
        source_ip=src_ip,
        dest_ip=scenario_info["dest_ip"],
        protocol=scenario_info["protocol"],
        port=scenario_info["port"],
        attack_type=scenario_info["attack_type"],
        risk_score=scenario_info["risk_score"],
        severity=scenario_info["severity"],
        confidence=scenario_info["confidence"],
        dataset_source="live_sensor",
        status="new",
        mitre_technique=scenario_info["mitre"],
        notes=f"Simulated {scenario_info['title']} triggered from SOC dashboard.",
    )
    db.add(alert)
    await db.flush()

    # 2. Add to live queue
    payload = {
        "type": "attack_alert",
        "id": alert.id,
        "title": scenario_info["title"],
        "source": src_ip,
        "dest": scenario_info["dest_ip"],
        "protocol": scenario_info["protocol"],
        "port": scenario_info["port"],
        "severity": scenario_info["severity"],
        "prediction": scenario_info["attack_type"],
        "riskScore": scenario_info["risk_score"],
        "confidence": int(scenario_info["confidence"] * 100),
        "timestamp": datetime.utcnow().isoformat(),
    }
    await _attack_queue.put(payload)
    await db.commit()

    return {"status": "success", "message": f"Injected {scenario_info['title']}", "alert_id": alert.id}


@router.websocket("/live")
@router.websocket("/ws")
async def websocket_traffic_feed(websocket: WebSocket):
    """High-frequency real-time packet telemetry & anomaly streaming."""
    await websocket.accept()
    
    protocols = ["TCP", "UDP", "HTTPS", "DNS", "SSH", "ICMP"]
    internal_ips = ["10.0.0.15", "10.0.0.20", "10.0.0.35", "10.0.0.50", "192.168.1.10"]
    external_ips = ["142.250.190.46", "104.244.42.1", "151.101.1.69", "8.8.8.8", "1.1.1.1"]

    try:
        while True:
            # Check for injected attacks
            if not _attack_queue.empty():
                attack_item = await _attack_queue.get()
                await websocket.send_json(attack_item)

            # Generate realistic live flow telemetry
            proto = random.choice(protocols)
            src_ip = random.choice(external_ips if random.random() > 0.4 else internal_ips)
            dst_ip = random.choice(internal_ips if src_ip in external_ips else external_ips)
            port = 443 if proto == "HTTPS" else (80 if proto == "TCP" else (53 if proto == "DNS" else random.randint(1024, 65535)))
            pkts = random.randint(2, 45)
            byte_count = pkts * random.randint(64, 1420)
            
            # Normal background flow
            payload = {
                "type": "telemetry",
                "source": src_ip,
                "dest": dst_ip,
                "srcPort": random.randint(30000, 60000),
                "dstPort": port,
                "protocol": proto,
                "packets": pkts,
                "bytes": byte_count,
                "threatLevel": "Low",
                "prediction": "Normal",
                "confidence": random.randint(95, 99),
                "riskScore": random.randint(2, 12),
                "timestamp": datetime.utcnow().isoformat(),
            }
            await websocket.send_json(payload)
            await asyncio.sleep(0.8)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[WebSocket] Error: {e}")

