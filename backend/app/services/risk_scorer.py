"""
Risk Scoring Engine — Stage 6 of the AI Analytics Pipeline.
Converts model predictions into enterprise risk scores (0-100) with severity bands.
"""

# Scoring rules per attack category
ATTACK_SCORES = {
    # CICIDS2017 attack types
    "DDoS": {"base": 85, "weight": 1.0},
    "DoS Hulk": {"base": 75, "weight": 0.9},
    "DoS GoldenEye": {"base": 75, "weight": 0.9},
    "DoS slowloris": {"base": 70, "weight": 0.85},
    "DoS Slowhttptest": {"base": 70, "weight": 0.85},
    "PortScan": {"base": 45, "weight": 0.6},
    "FTP-Patator": {"base": 65, "weight": 0.8},
    "SSH-Patator": {"base": 70, "weight": 0.85},
    "Bot": {"base": 80, "weight": 0.95},
    "Web Attack – Brute Force": {"base": 60, "weight": 0.75},
    "Web Attack – XSS": {"base": 65, "weight": 0.8},
    "Web Attack – Sql Injection": {"base": 75, "weight": 0.9},
    "Infiltration": {"base": 90, "weight": 1.0},
    "Heartbleed": {"base": 95, "weight": 1.0},
    # UNSW-NB15 attack types
    "Fuzzers": {"base": 40, "weight": 0.5},
    "Analysis": {"base": 50, "weight": 0.6},
    "Backdoors": {"base": 85, "weight": 1.0},
    "Backdoor": {"base": 85, "weight": 1.0},
    "DoS": {"base": 75, "weight": 0.9},
    "Exploits": {"base": 80, "weight": 0.95},
    "Generic": {"base": 55, "weight": 0.65},
    "Reconnaissance": {"base": 45, "weight": 0.55},
    "Shellcode": {"base": 90, "weight": 1.0},
    "Worms": {"base": 92, "weight": 1.0},
    "Normal": {"base": 5, "weight": 0.1},
    "BENIGN": {"base": 5, "weight": 0.1},
}


def get_severity(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    elif score >= 51:
        return "HIGH"
    elif score >= 31:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_risk_score(
    attack_type: str,
    confidence: float,
    frequency: int = 1,
) -> dict:
    """
    Calculate risk score from attack type, model confidence, and frequency.
    
    Args:
        attack_type: Predicted attack class name
        confidence: Model prediction probability (0.0-1.0)
        frequency: Number of similar events in the last window (default 1)
    
    Returns:
        dict with risk_score (0-100), severity (LOW/MEDIUM/HIGH/CRITICAL)
    """
    attack_info = ATTACK_SCORES.get(attack_type, {"base": 30, "weight": 0.5})
    
    base_score = attack_info["base"]
    weight = attack_info["weight"]
    
    # Confidence multiplier: scale from 0.6 to 1.0 of base score
    confidence_factor = 0.6 + (confidence * 0.4)
    
    # Frequency bonus: repeated events increase score (capped at +15)
    freq_bonus = min(15, (frequency - 1) * 3)
    
    raw_score = (base_score * weight * confidence_factor) + freq_bonus
    risk_score = max(0, min(100, int(round(raw_score))))
    
    severity = get_severity(risk_score)
    
    return {
        "risk_score": risk_score,
        "severity": severity,
        "attack_type": attack_type,
        "confidence": round(confidence, 4),
    }
