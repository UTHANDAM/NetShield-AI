from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from database import fetch_all, fetch_one
from auth import get_optional_user

threat_router = APIRouter(tags=['Threats'])
threat_bp = threat_router

@threat_router.get('/threats')
async def get_threats(
    limit: int = 50,
    page: int = 1,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    current_user: Optional[dict] = Depends(get_optional_user)
):
    conditions = []
    params = []

    # 1. Severity filter (case-insensitive, supporting CRITICAL, HIGH, MEDIUM, LOW)
    if severity:
        sev_clean = severity.strip()
        if sev_clean and sev_clean.upper() not in ["ALL", "ALL SEVERITIES", ""]:
            conditions.append("UPPER(severity) = UPPER(%s)")
            params.append(sev_clean)

    # 2. Search filter (case-insensitive for IP, attack type, protocol)
    if search:
        s_clean = search.strip()
        if s_clean:
            search_pattern = f"%{s_clean}%"
            conditions.append(
                """(
                    source_ip ILIKE %s OR
                    destination_ip ILIKE %s OR
                    attack_type ILIKE %s OR
                    protocol ILIKE %s
                )"""
            )
            params.extend([search_pattern, search_pattern, search_pattern, search_pattern])

    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""

    # Count total matching rows for pagination
    count_sql = f"SELECT COUNT(*) AS total FROM threats{where_clause}"
    count_row = fetch_one(count_sql, tuple(params) if params else None)
    total = int(count_row.get("total", 0)) if count_row else 0

    safe_limit = max(1, min(limit, 500))
    safe_page = max(1, page)
    offset = (safe_page - 1) * safe_limit

    data_sql = f"""
        SELECT id, attack_type, source_ip, destination_ip, protocol,
               confidence, risk_score, severity, status, detected_at
        FROM threats
        {where_clause}
        ORDER BY detected_at DESC, id DESC
        LIMIT %s OFFSET %s
    """
    query_params = list(params) + [safe_limit, offset]
    threats = fetch_all(data_sql, tuple(query_params))

    return {
        'threats': threats or [],
        'total': total,
        'page': safe_page,
        'limit': safe_limit
    }

@threat_router.get('/threats/{threat_id}')
async def get_threat_detail(threat_id: int, current_user: Optional[dict] = Depends(get_optional_user)):
    threat = fetch_one("SELECT * FROM threats WHERE id = %s", (threat_id,))
    if not threat:
        raise HTTPException(status_code=404, detail='Threat record not found.')
    return {'threat': threat}
