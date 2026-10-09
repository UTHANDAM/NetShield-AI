from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query

from database import fetch_all, fetch_one
from auth import get_optional_user
from ml.evaluation import get_production_model_evaluation
from services.threat_intel_service import check_ip_reputation


analytics_router = APIRouter(tags=["Analytics & Threat Intelligence"])
analytics_bp = analytics_router


def safe_metric(value):
    """Return a real metric when available, otherwise None."""
    if value is None:
        return None

    try:
        return round(float(value), 2)
    except (TypeError, ValueError):
        return None


def safe_count(row, key="count"):
    """Safely extract a database count."""
    if not row:
        return 0

    value = row.get(key, 0)

    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


@analytics_router.get("/threat-intelligence")
async def get_threat_intelligence(
    current_user: Optional[dict] = Depends(get_optional_user)
):
    # ------------------------------------------------------------------
    # 1. Threat intelligence signatures from PostgreSQL
    # ------------------------------------------------------------------
    threat_intel = fetch_all(
        """
        SELECT attack_type,
               severity,
               risk_score,
               description,
               recommended_response
        FROM threat_intelligence
        """
    )

    # ------------------------------------------------------------------
    # 2. Real insights from threats table
    # ------------------------------------------------------------------
    top_attack_row = fetch_one(
        """
        SELECT attack_type, COUNT(*) AS cnt
        FROM threats
        WHERE UPPER(attack_type) NOT IN ('BENIGN', 'NORMAL')
        GROUP BY attack_type
        ORDER BY cnt DESC
        LIMIT 1
        """
    )

    most_freq_attack = (
        top_attack_row["attack_type"]
        if top_attack_row
        else "No data"
    )

    top_src_row = fetch_one(
        """
        SELECT source_ip, COUNT(*) AS cnt
        FROM threats
        WHERE source_ip IS NOT NULL
          AND source_ip NOT IN ('Not available', '127.0.0.1')
        GROUP BY source_ip
        ORDER BY cnt DESC
        LIMIT 1
        """
    )

    top_src_ip = (
        top_src_row["source_ip"]
        if top_src_row
        else "No data"
    )

    top_dst_row = fetch_one(
        """
        SELECT destination_ip, COUNT(*) AS cnt
        FROM threats
        WHERE destination_ip IS NOT NULL
          AND destination_ip NOT IN ('Not available', '127.0.0.1')
        GROUP BY destination_ip
        ORDER BY cnt DESC
        LIMIT 1
        """
    )

    top_dst_ip = (
        top_dst_row["destination_ip"]
        if top_dst_row
        else "No data"
    )

    insights = {
        "most_frequent_attack": most_freq_attack,
        "top_source_ip": top_src_ip,
        "top_destination_ip": top_dst_ip,
    }

    # ------------------------------------------------------------------
    # 3. Real risk distribution from predictions
    # ------------------------------------------------------------------
    traffic_total_row = fetch_one(
        "SELECT COUNT(*) AS cnt FROM predictions"
    )
    total_records = safe_count(traffic_total_row, "cnt")

    benign_cnt_row = fetch_one(
        """
        SELECT COUNT(*) AS cnt
        FROM predictions
        WHERE UPPER(predicted_label) IN ('BENIGN', 'NORMAL')
        """
    )
    low_count = safe_count(benign_cnt_row, "cnt")

    ftp_cnt_row = fetch_one(
        """
        SELECT COUNT(*) AS cnt
        FROM predictions
        WHERE UPPER(predicted_label) LIKE '%FTP%'
        """
    )
    med_count = safe_count(ftp_cnt_row, "cnt")

    ssh_cnt_row = fetch_one(
        """
        SELECT COUNT(*) AS cnt
        FROM predictions
        WHERE UPPER(predicted_label) LIKE '%SSH%'
        """
    )
    high_count = safe_count(ssh_cnt_row, "cnt")

    ddos_cnt_row = fetch_one(
        """
        SELECT COUNT(*) AS cnt
        FROM predictions
        WHERE UPPER(predicted_label) LIKE '%DDOS%'
        """
    )
    crit_count = safe_count(ddos_cnt_row, "cnt")

    denominator = max(1, total_records)

    risk_distribution = [
        {
            "risk_category": "Low Risk (0-30)",
            "count": low_count,
            "color": "#22C55E",
            "percentage": round((low_count / denominator) * 100, 1),
        },
        {
            "risk_category": "Medium Risk (31-60)",
            "count": med_count,
            "color": "#F59E0B",
            "percentage": round((med_count / denominator) * 100, 1),
        },
        {
            "risk_category": "High Risk (61-80)",
            "count": high_count,
            "color": "#F97316",
            "percentage": round((high_count / denominator) * 100, 1),
        },
        {
            "risk_category": "Critical Risk (81-100)",
            "count": crit_count,
            "color": "#EF4444",
            "percentage": round((crit_count / denominator) * 100, 1),
        },
    ]

    # ------------------------------------------------------------------
    # 4. Random Forest model evaluation
    # ------------------------------------------------------------------
    rf_eval = get_production_model_evaluation()

    if not isinstance(rf_eval, dict):
        rf_eval = {}

    acc_val = safe_metric(rf_eval.get("accuracy"))
    has_gt = rf_eval.get("has_ground_truth", False)
    class_metrics = rf_eval.get("class_metrics", [])

    class_colors = {
        "BENIGN": "#22C55E",
        "DDoS": "#EF4444",
        "FTP-Patator": "#F59E0B",
        "SSH-Patator": "#F97316",
    }

    threat_performance_metrics = []
    if has_gt and class_metrics:
        for cm in class_metrics:
            cname = cm.get("class_name")
            acc = cm.get("accuracy")
            conf = cm.get("confidence")
            if acc is not None and isinstance(acc, (int, float)):
                threat_performance_metrics.append({
                    "class_name": cname,
                    "accuracy": round(float(acc), 1),
                    "confidence": round(float(conf), 1) if conf is not None else None,
                    "color": class_colors.get(cname, "#3B82F6"),
                })
    else:
        threat_performance_metrics = []

    # ------------------------------------------------------------------
    # 5. Critical threats from PostgreSQL
    # ------------------------------------------------------------------
    critical_threats = fetch_all(
        """
        SELECT id,
               attack_type,
               source_ip,
               destination_ip,
               confidence,
               risk_score,
               severity,
               detected_at
        FROM threats
        WHERE UPPER(severity) = 'CRITICAL'
        ORDER BY id DESC
        LIMIT 15
        """
    )

    for ct in critical_threats:
        if ct.get("detected_at") and not isinstance(
            ct["detected_at"], str
        ):
            ct["detected_at"] = str(ct["detected_at"])

    # ------------------------------------------------------------------
    # 6. Top attackers from PostgreSQL
    # ------------------------------------------------------------------
    top_attackers_raw = fetch_all(
        """
        SELECT source_ip,
               attack_type,
               COUNT(*) AS attack_count,
               AVG(risk_score) AS avg_risk_score
        FROM threats
        WHERE source_ip IS NOT NULL
          AND source_ip NOT IN ('127.0.0.1', 'Not available')
        GROUP BY source_ip, attack_type
        ORDER BY attack_count DESC
        LIMIT 5
        """
    )

    top_attackers = []

    for ta in top_attackers_raw:
        risk = safe_metric(ta.get("avg_risk_score"))

        if risk is None:
            risk = 0

        top_attackers.append(
            {
                "source_ip": ta["source_ip"],
                "attack_type": ta["attack_type"],
                "attack_count": int(ta["attack_count"]),
                "avg_risk_score": risk,
                "reputation": {
                    "is_malicious": risk >= 70,
                    "abuse_score": min(100, int(risk)),
                },
            }
        )

    return {
        "threat_intelligence": threat_intel or [],
        "top_attackers": top_attackers,
        "insights": insights,
        "risk_distribution": risk_distribution,
        "threat_performance_metrics": threat_performance_metrics,
        "has_ground_truth": has_gt,
        "has_verified_evaluation": has_gt and len(threat_performance_metrics) > 0,
        "critical_threats": critical_threats or [],
        "provider_status": {
            "provider": "AbuseIPDB",
            "api_configured": True,
            "caching_database": "PostgreSQL (Primary)",
        },
    }


@analytics_router.get("/threat-intelligence/lookup")
async def lookup_threat_ip(
    ip: str = Query("192.168.1.105"),
    current_user: Optional[dict] = Depends(get_optional_user),
):
    rep = check_ip_reputation(ip)

    return {
        "ip_address": ip,
        "reputation": rep,
    }


@analytics_router.get("/weekly-security-trends")
async def get_weekly_trends(
    current_user: Optional[dict] = Depends(get_optional_user)
):
    # ------------------------------------------------------------------
    # Real Random Forest evaluation
    # ------------------------------------------------------------------
    rf_eval = get_production_model_evaluation()

    if not isinstance(rf_eval, dict):
        rf_eval = {}

    acc = safe_metric(rf_eval.get("accuracy"))

    # ------------------------------------------------------------------
    # Real database totals
    # ------------------------------------------------------------------
    threat_row = fetch_one(
        "SELECT COUNT(*) AS count FROM threats"
    )
    total_threats = safe_count(threat_row)

    crit_row = fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM threats
        WHERE UPPER(severity) = 'CRITICAL'
        """
    )
    critical_threats = safe_count(crit_row)

    alert_row = fetch_one(
        "SELECT COUNT(*) AS count FROM security_alerts"
    )
    security_alerts = safe_count(alert_row)

    traffic_row = fetch_one(
        "SELECT COUNT(*) AS count FROM predictions"
    )
    total_traffic = safe_count(traffic_row)

    attack_rate = (
        round((total_threats / total_traffic) * 100, 2)
        if total_traffic > 0
        else 0.0
    )

    # ------------------------------------------------------------------
    # Real attack distribution
    # ------------------------------------------------------------------
    raw_attacks = fetch_all(
        """
        SELECT predicted_label AS name,
               COUNT(*) AS count
        FROM predictions
        GROUP BY predicted_label
        ORDER BY count DESC
        """
    )

    attack_colors = {
        "BENIGN": "#22C55E",
        "NORMAL": "#22C55E",
        "DDoS": "#EF4444",
        "FTP-Patator": "#F59E0B",
        "SSH-Patator": "#F97316",
    }

    attack_type_distribution = []

    for attack in raw_attacks:
        count = int(attack["count"])

        attack_type_distribution.append(
            {
                "name": attack["name"],
                "count": count,
                "percentage": round(
                    (count / max(1, total_traffic)) * 100,
                    1,
                ),
                "color": attack_colors.get(
                    attack["name"],
                    "#3B82F6",
                ),
            }
        )

    # ------------------------------------------------------------------
    # Real severity distribution
    # ------------------------------------------------------------------
    raw_sev = fetch_all(
        """
        SELECT severity AS name,
               COUNT(*) AS count
        FROM predictions
        GROUP BY severity
        ORDER BY count DESC
        """
    )

    sev_colors = {
        "CRITICAL": "#EF4444",
        "HIGH": "#F97316",
        "MEDIUM": "#F59E0B",
        "LOW": "#22C55E",
    }

    severity_distribution = []

    for severity in raw_sev:
        count = int(severity["count"])
        severity_name = severity["name"]

        severity_distribution.append(
            {
                "name": (
                    severity_name.capitalize()
                    if severity_name
                    else "Unknown"
                ),
                "value": count,
                "percentage": round(
                    (count / max(1, total_traffic)) * 100,
                    1,
                ),
                "color": sev_colors.get(
                    str(severity_name).upper(),
                    "#3B82F6",
                ),
            }
        )

    # ------------------------------------------------------------------
    # Real daily trends
    # ------------------------------------------------------------------
    daily_attack_rows = fetch_all(
        """
        SELECT DATE(detected_at) AS day,
               COUNT(*) AS attacks,
               COUNT(*) FILTER (
                   WHERE UPPER(severity) = 'CRITICAL'
               ) AS critical_count
        FROM threats
        WHERE detected_at >= CURRENT_DATE - INTERVAL '6 days'
        GROUP BY DATE(detected_at)
        ORDER BY DATE(detected_at)
        """
    )

    if not daily_attack_rows:
        daily_attack_rows = fetch_all(
            """
            SELECT DATE(detected_at) AS day,
                   COUNT(*) AS attacks,
                   COUNT(*) FILTER (
                       WHERE UPPER(severity) = 'CRITICAL'
                   ) AS critical_count
            FROM threats
            WHERE detected_at >= (SELECT MAX(DATE(detected_at)) FROM threats) - INTERVAL '6 days'
            GROUP BY DATE(detected_at)
            ORDER BY DATE(detected_at)
            """
        )

    daily_attack_trend = []

    for row in daily_attack_rows:
        day_value = row.get("day")

        if hasattr(day_value, "strftime"):
            display_date = day_value.strftime("%b %d")
            short_day = day_value.strftime("%a")
            date_value = day_value.isoformat()
            full_day = day_value.strftime("%A")
        else:
            date_value = str(day_value)
            short_day = str(day_value)[:3]
            display_date = str(day_value)
            full_day = str(day_value)

        daily_attack_trend.append(
            {
                "day": full_day,
                "short_day": short_day,
                "date": date_value,
                "display_date": display_date,
                "attacks": int(row.get("attacks") or 0),
                "critical_count": int(
                    row.get("critical_count") or 0
                ),
                "benign_count": 0,
            }
        )

    # ------------------------------------------------------------------
    # Real daily alerts
    # ------------------------------------------------------------------
    daily_alert_rows = fetch_all(
        """
        SELECT DATE(created_at) AS day,
               COUNT(*) AS alerts,
               COUNT(*) FILTER (
                   WHERE UPPER(severity) = 'CRITICAL'
               ) AS critical_alerts
        FROM security_alerts
        WHERE created_at >= CURRENT_DATE - INTERVAL '6 days'
        GROUP BY DATE(created_at)
        ORDER BY DATE(created_at)
        """
    )

    if not daily_alert_rows:
        daily_alert_rows = fetch_all(
            """
            SELECT DATE(created_at) AS day,
                   COUNT(*) AS alerts,
                   COUNT(*) FILTER (
                       WHERE UPPER(severity) = 'CRITICAL'
                   ) AS critical_alerts
            FROM security_alerts
            WHERE created_at >= (SELECT MAX(DATE(created_at)) FROM security_alerts) - INTERVAL '6 days'
            GROUP BY DATE(created_at)
            ORDER BY DATE(created_at)
            """
        )

    daily_alert_trend = []

    for row in daily_alert_rows:
        day_value = row.get("day")

        if hasattr(day_value, "strftime"):
            short_day = day_value.strftime("%a")
            date_value = day_value.isoformat()
            full_day = day_value.strftime("%A")
        else:
            date_value = str(day_value)
            short_day = str(day_value)[:3]
            full_day = str(day_value)

        daily_alert_trend.append(
            {
                "day": full_day,
                "short_day": short_day,
                "date": date_value,
                "alerts": int(row.get("alerts") or 0),
                "critical_alerts": int(
                    row.get("critical_alerts") or 0
                ),
            }
        )

    # ------------------------------------------------------------------
    # Threat activity by day
    # ------------------------------------------------------------------
    threat_activity_by_day = [
        {
            "day": item["day"],
            "short_day": item["short_day"],
            "threats": item["attacks"],
            "critical": item["critical_count"],
        }
        for item in daily_attack_trend
    ]

    model_performance = {
        "model_name": "Random Forest (Production Model)",
        "accuracy": safe_metric(rf_eval.get("accuracy")),
        "precision": safe_metric(rf_eval.get("precision")),
        "recall": safe_metric(rf_eval.get("recall")),
        "f1_score": safe_metric(rf_eval.get("f1_score")),
    }

    malicious_attacks = [
        a for a in attack_type_distribution
        if a["name"].upper() not in ("BENIGN", "NORMAL")
    ]
    most_detected = (
        malicious_attacks[0]["name"]
        if malicious_attacks
        else (
            attack_type_distribution[0]["name"]
            if attack_type_distribution
            else "No data"
        )
    )

    weekly_summary = {
        "most_detected_attack": most_detected,
        "highest_risk_day": (
            max(
                daily_attack_trend,
                key=lambda x: x["critical_count"],
            )["day"]
            if daily_attack_trend
            else "No data"
        ),
        "total_attacks": total_threats,
        "alerts_generated": security_alerts,
        "detection_accuracy": (
            f"{acc}%"
            if acc is not None
            else "N/A"
        ),
    }

    return {
        "summary": {
            "total_threats": total_threats,
            "critical_threats": critical_threats,
            "security_alerts": security_alerts,
            "attack_rate": attack_rate,
            "accuracy": acc,
            "total_weekly_traffic": total_traffic,
            "total_weekly_threats": total_threats,
            "weekly_threat_rate": f"{attack_rate}%",
            "detection_accuracy": (
                f"{acc}%"
                if acc is not None
                else "N/A"
            ),
        },
        "daily_attack_trend": daily_attack_trend,
        "attack_type_distribution": attack_type_distribution,
        "severity_distribution": severity_distribution,
        "daily_alert_trend": daily_alert_trend,
        "threat_activity_by_day": threat_activity_by_day,
        "model_performance": model_performance,
        "weekly_summary": weekly_summary,
        "weekly_trends": daily_attack_trend,
        "model_evaluation": rf_eval,
    }


@analytics_router.get("/security-analytics")
async def get_security_analytics(
    current_user: Optional[dict] = Depends(get_optional_user)
):
    # ------------------------------------------------------------------
    # Random Forest evaluation
    # ------------------------------------------------------------------
    rf_eval = get_production_model_evaluation()

    if not isinstance(rf_eval, dict):
        rf_eval = {}

    # ------------------------------------------------------------------
    # Real PostgreSQL overview
    # ------------------------------------------------------------------
    traffic_row = fetch_one(
        "SELECT COUNT(*) AS cnt FROM predictions"
    )
    total_traffic = safe_count(traffic_row, "cnt")

    benign_row = fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM predictions
        WHERE UPPER(predicted_label) IN ('BENIGN', 'NORMAL')
        """
    )
    benign_count = safe_count(benign_row)

    threat_row = fetch_one(
        "SELECT COUNT(*) AS cnt FROM threats"
    )

    total_threats = safe_count(threat_row, "cnt")

    if not threat_row and total_traffic >= benign_count:
        total_threats = total_traffic - benign_count

    crit_row = fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM threats
        WHERE UPPER(severity) = 'CRITICAL'
        """
    )
    critical_threats = safe_count(crit_row)

    incident_row = fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM incidents
        WHERE status NOT IN ('RESOLVED', 'CLOSED')
        """
    )
    active_incidents = safe_count(incident_row)

    avg_risk_row = fetch_one(
        "SELECT AVG(risk_score) AS avg_risk FROM predictions"
    )

    avg_risk = (
        round(float(avg_risk_row["avg_risk"]), 1)
        if avg_risk_row
        and avg_risk_row.get("avg_risk") is not None
        else 0.0
    )

    threat_pct = (
        round((total_threats / total_traffic) * 100, 1)
        if total_traffic > 0
        else 0.0
    )

    benign_pct = (
        round((benign_count / total_traffic) * 100, 1)
        if total_traffic > 0
        else 0.0
    )

    crit_pct = (
        round((critical_threats / total_threats) * 100, 1)
        if total_threats > 0
        else 0.0
    )

    # ------------------------------------------------------------------
    # Real attack distribution
    # ------------------------------------------------------------------
    raw_attacks = fetch_all(
        """
        SELECT predicted_label AS attack_type,
               COUNT(*) AS count
        FROM predictions
        GROUP BY predicted_label
        ORDER BY count DESC
        """
    )

    attack_colors = {
        "BENIGN": "#22C55E",
        "NORMAL": "#22C55E",
        "DDoS": "#EF4444",
        "FTP-Patator": "#F59E0B",
        "SSH-Patator": "#F97316",
    }

    attack_distribution = []

    for attack in raw_attacks:
        count = int(attack["count"])

        attack_distribution.append(
            {
                "attack_type": attack["attack_type"],
                "name": attack["attack_type"],
                "count": count,
                "value": count,
                "percentage": round(
                    (count / max(1, total_traffic)) * 100,
                    1,
                ),
                "color": attack_colors.get(
                    attack["attack_type"],
                    "#3B82F6",
                ),
            }
        )

    # ------------------------------------------------------------------
    # Real severity distribution
    # ------------------------------------------------------------------
    raw_sev = fetch_all(
        """
        SELECT severity,
               COUNT(*) AS count
        FROM predictions
        GROUP BY severity
        ORDER BY count DESC
        """
    )

    sev_colors = {
        "CRITICAL": "#EF4444",
        "HIGH": "#F97316",
        "MEDIUM": "#F59E0B",
        "LOW": "#22C55E",
    }

    severity_distribution = []

    for severity in raw_sev:
        count = int(severity["count"])

        severity_distribution.append(
            {
                "severity": severity["severity"],
                "count": count,
                "percentage": round(
                    (count / max(1, total_traffic)) * 100,
                    1,
                ),
                "color": sev_colors.get(
                    str(severity["severity"]).upper(),
                    "#3B82F6",
                ),
            }
        )

    # ------------------------------------------------------------------
    # Real threat activity timeline
    # ------------------------------------------------------------------
    span_check = fetch_one(
        """
        SELECT COUNT(DISTINCT EXTRACT(HOUR FROM detected_at)) AS hour_count,
               COUNT(DISTINCT TO_CHAR(detected_at, 'HH24:MI:SS')) AS sec_count
        FROM threats
        WHERE detected_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
        """
    )
    hour_count = safe_count(span_check, "hour_count")
    sec_count = safe_count(span_check, "sec_count")

    if sec_count == 0:
        span_check = fetch_one(
            """
            SELECT COUNT(DISTINCT EXTRACT(HOUR FROM detected_at)) AS hour_count,
                   COUNT(DISTINCT TO_CHAR(detected_at, 'HH24:MI:SS')) AS sec_count
            FROM threats
            WHERE detected_at >= (SELECT MAX(detected_at) FROM threats) - INTERVAL '24 hours'
            """
        )
        hour_count = safe_count(span_check, "hour_count")
        sec_count = safe_count(span_check, "sec_count")
        fallback_clause = "WHERE detected_at >= (SELECT MAX(detected_at) FROM threats) - INTERVAL '24 hours'"
    else:
        fallback_clause = "WHERE detected_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'"

    if hour_count > 1:
        threat_activity_rows = fetch_all(
            f"""
            SELECT TO_CHAR(detected_at, 'HH24:00') AS time,
                   COUNT(*) AS threats,
                   ROUND(AVG(risk_score)::numeric, 1) AS risk
            FROM threats
            {fallback_clause}
            GROUP BY TO_CHAR(detected_at, 'HH24:00')
            ORDER BY MIN(detected_at)
            LIMIT 30
            """
        )
    elif sec_count > 0:
        threat_activity_rows = fetch_all(
            f"""
            SELECT TO_CHAR(detected_at, 'HH24:MI:SS') AS time,
                   COUNT(*) AS threats,
                   ROUND(AVG(risk_score)::numeric, 1) AS risk
            FROM threats
            {fallback_clause}
            GROUP BY TO_CHAR(detected_at, 'HH24:MI:SS')
            ORDER BY MIN(detected_at)
            LIMIT 30
            """
        )
    else:
        threat_activity_rows = []

    threat_activity = [
        {
            "time": row["time"],
            "threats": int(row.get("threats") or 0),
            "risk": safe_metric(row.get("risk")) or 0,
        }
        for row in threat_activity_rows
    ]

    # ------------------------------------------------------------------
    # Top sources from PostgreSQL
    # ------------------------------------------------------------------
    top_sources = fetch_all(
        """
        SELECT source_ip,
                attack_type,
                COUNT(*) AS attempts,
                MAX(severity) AS risk
        FROM threats
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip, attack_type
        ORDER BY attempts DESC
        LIMIT 5
        """
    )

    # ------------------------------------------------------------------
    # Active threats from PostgreSQL
    # ------------------------------------------------------------------
    active_threats_raw = fetch_all(
        """
        SELECT id,
               attack_type,
               source_ip,
               destination_ip,
               protocol,
               confidence,
               risk_score,
               severity,
               detected_at,
               status
        FROM threats
        ORDER BY detected_at DESC
        LIMIT 8
        """
    )

    active_threats = []

    for threat in active_threats_raw:
        detected_at = threat.get("detected_at")

        if hasattr(detected_at, "isoformat"):
            timestamp = detected_at.isoformat()
        else:
            timestamp = str(detected_at) if detected_at else None

        confidence = (
            float(threat["confidence"])
            if threat.get("confidence") is not None
            else None
        )

        risk_score = (
            int(threat["risk_score"])
            if threat.get("risk_score") is not None
            else None
        )

        active_threats.append(
            {
                "id": threat["id"],
                "attack_type": threat["attack_type"],
                "source_ip": threat.get("source_ip"),
                "destination_ip": threat.get("destination_ip"),
                "protocol": threat.get("protocol"),
                "confidence": confidence,
                "risk_score": risk_score,
                "severity": threat.get("severity"),
                "timestamp": timestamp,
                "status": threat.get("status"),
            }
        )

    # ------------------------------------------------------------------
    # Recent security events
    # ------------------------------------------------------------------
    recent_events_raw = fetch_all(
        """
        SELECT alert_type AS event,
               alert_type AS type,
               severity,
               created_at AS timestamp,
               status
        FROM security_alerts
        ORDER BY created_at DESC
        LIMIT 6
        """
    )

    recent_events = []

    for event in recent_events_raw:
        timestamp = event.get("timestamp")

        if hasattr(timestamp, "isoformat"):
            event_time = timestamp.isoformat()
        else:
            event_time = str(timestamp) if timestamp else None

        recent_events.append(
            {
                "event": event.get("event"),
                "type": event.get("type"),
                "severity": event.get("severity"),
                "time": event_time,
                "status": event.get("status"),
            }
        )

    # ------------------------------------------------------------------
    # Traffic analytics
    # ------------------------------------------------------------------
    traffic_trend_rows = fetch_all(
        """
        SELECT TO_CHAR(timestamp, 'HH24:MI:SS') AS time,
               COUNT(*) FILTER (WHERE UPPER(predicted_label) IN ('BENIGN', 'NORMAL')) AS benign,
               COUNT(*) FILTER (WHERE UPPER(predicted_label) NOT IN ('BENIGN', 'NORMAL')) AS threats,
               COUNT(*) AS total
        FROM predictions
        GROUP BY TO_CHAR(timestamp, 'HH24:MI:SS')
        ORDER BY MIN(timestamp)
        LIMIT 30
        """
    )

    traffic_trend = [
        {
            "time": row["time"],
            "benign": int(row.get("benign") or 0),
            "threats": int(row.get("threats") or 0),
            "total": int(row.get("total") or 0),
        }
        for row in traffic_trend_rows
    ]

    traffic_analytics = {
        "total_traffic": total_traffic,
        "benign_traffic": benign_count,
        "threat_traffic": total_threats,
        "benign_percentage": benign_pct,
        "threat_percentage": threat_pct,
        "traffic_trend": traffic_trend,
    }

    # ------------------------------------------------------------------
    # Real Random Forest performance
    # ------------------------------------------------------------------
    ai_performance = {
        "accuracy": safe_metric(rf_eval.get("accuracy")),
        "precision": safe_metric(rf_eval.get("precision")),
        "recall": safe_metric(rf_eval.get("recall")),
        "f1_score": safe_metric(rf_eval.get("f1_score")),
        "latency_ms": None,
        "test_samples": total_traffic,
        "active_model": "Random Forest (Production Model)",
        "features": 78,
        "classes": 4,
    }

    # ------------------------------------------------------------------
    # Real attack trends from the last 24 hours
    # ------------------------------------------------------------------
    if hour_count > 1:
        attack_trend_rows = fetch_all(
            f"""
            SELECT TO_CHAR(detected_at, 'HH24:00') AS time,
                   attack_type,
                   COUNT(*) AS count
            FROM threats
            {fallback_clause}
            GROUP BY TO_CHAR(detected_at, 'HH24:00'), attack_type
            ORDER BY MIN(detected_at)
            """
        )
    elif sec_count > 0:
        attack_trend_rows = fetch_all(
            f"""
            SELECT TO_CHAR(detected_at, 'HH24:MI:SS') AS time,
                   attack_type,
                   COUNT(*) AS count
            FROM threats
            {fallback_clause}
            GROUP BY TO_CHAR(detected_at, 'HH24:MI:SS'), attack_type
            ORDER BY MIN(detected_at)
            """
        )
    else:
        attack_trend_rows = []

    attack_trends_map = {}

    for row in attack_trend_rows:
        time_key = row.get("time")
        attack_type = row.get("attack_type")
        count = int(row.get("count") or 0)

        if time_key not in attack_trends_map:
            attack_trends_map[time_key] = {
                "time": time_key,
                "DDoS": 0,
                "FTP-Patator": 0,
                "SSH-Patator": 0,
            }

        attack_trends_map[time_key][attack_type] = count

    attack_trends = list(attack_trends_map.values())

    # ------------------------------------------------------------------
    # Dynamic risk analysis
    # ------------------------------------------------------------------
    risk_analysis = []

    for attack in raw_attacks:
        attack_type = attack["attack_type"]
        count = int(attack["count"])

        percentage = round(
            (count / max(1, total_traffic)) * 100,
            1,
        )

        attack_upper = str(attack_type).upper()

        if attack_upper in ("BENIGN", "NORMAL"):
            risk = 5
            severity = "LOW"
        elif "DDOS" in attack_upper:
            risk = 95
            severity = "CRITICAL"
        elif "SSH" in attack_upper:
            risk = 80
            severity = "HIGH"
        elif "FTP" in attack_upper:
            risk = 65
            severity = "MEDIUM"
        else:
            risk = 70
            severity = "MEDIUM"

        risk_analysis.append(
            {
                "attack_type": attack_type,
                "detected": count,
                "event_count": count,
                "risk_score": risk,
                "severity": severity,
                "percentage": percentage,
            }
        )

    # ------------------------------------------------------------------
    # Final response
    # ------------------------------------------------------------------
    return {
        "status": "success",
        "overview": {
            "total_traffic": total_traffic,
            "total_threats": total_threats,
            "benign_traffic": benign_count,
            "critical_threats": critical_threats,
            "active_incidents": active_incidents,
            "threat_percentage": threat_pct,
            "benign_percentage": benign_pct,
            "critical_percentage": crit_pct,
            "avg_risk_score": avg_risk,
            "security_status": (
                "CRITICAL THREATS DETECTED"
                if critical_threats > 0
                else (
                    "THREATS DETECTED"
                    if total_threats > 0
                    else "NORMAL MONITORING"
                )
            ),
            "detection_rate": None,
        },
        "threat_activity": threat_activity,
        "attack_distribution": attack_distribution,
        "severity_distribution": severity_distribution,
        "risk_analysis": risk_analysis,
        "top_sources": top_sources or [],
        "traffic_analytics": traffic_analytics,
        "active_threats": active_threats,
        "recent_events": recent_events,
        "ai_performance": ai_performance,
        "attack_trends": attack_trends,
        "model_performance": rf_eval,
    }