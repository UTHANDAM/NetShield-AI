"""
Dataset Loader Service — Stage 1+2 of the AI Analytics Pipeline.
Loads CICIDS2017 and UNSW-NB15, preprocesses, samples, and inserts into MongoDB + Postgres.
"""
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timezone, timedelta
import random
import asyncio
from app.config import settings
from app.services.risk_scorer import calculate_risk_score


# ── IP address generators for datasets missing IP columns ──────────────────

INTERNAL_SUBNETS = ["192.168.1", "192.168.2", "10.0.0", "10.0.1", "172.16.0"]
EXTERNAL_IPS = [
    "203.0.113.45", "198.51.100.23", "185.220.101.1", "45.33.32.156",
    "104.21.34.89", "91.189.92.11", "151.101.1.140", "142.250.185.46",
    "52.96.108.170", "13.107.42.14", "157.240.1.35", "31.13.71.36",
    "216.58.213.14", "172.217.14.206", "185.125.190.17", "93.184.216.34",
]

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMTP"]


def _gen_ip(subnet_list):
    subnet = random.choice(subnet_list)
    return f"{subnet}.{random.randint(1, 254)}"


# ── CICIDS2017 Loader ─────────────────────────────────────────────────────

def load_cicids2017(sample_per_file: int = 50000) -> pd.DataFrame:
    """Load all 8 CICIDS2017 CSV files, sample, and combine."""
    data_dir = Path(settings.CICIDS_PATH)
    all_frames = []

    csv_files = sorted(data_dir.glob("*.csv"))
    print(f"[CICIDS2017] Found {len(csv_files)} CSV files")

    for csv_file in csv_files:
        try:
            print(f"  Loading: {csv_file.name}")
            df = pd.read_csv(csv_file, low_memory=False, encoding='utf-8', on_bad_lines='skip')
            df.columns = df.columns.str.strip()

            # Sample
            if len(df) > sample_per_file:
                # Stratified: keep all attack rows, sample benign
                attack_rows = df[df['Label'] != 'BENIGN']
                benign_rows = df[df['Label'] == 'BENIGN']
                benign_sample_size = max(0, sample_per_file - len(attack_rows))
                if len(benign_rows) > benign_sample_size and benign_sample_size > 0:
                    benign_rows = benign_rows.sample(n=benign_sample_size, random_state=42)
                df = pd.concat([attack_rows, benign_rows], ignore_index=True)

            all_frames.append(df)
            print(f"    Kept {len(df)} rows ({len(df[df['Label'] != 'BENIGN'])} attacks)")
        except Exception as e:
            print(f"    ERROR loading {csv_file.name}: {e}")

    if not all_frames:
        return pd.DataFrame()

    combined = pd.concat(all_frames, ignore_index=True)
    print(f"[CICIDS2017] Total combined: {len(combined)} rows")
    return combined


def preprocess_cicids(df: pd.DataFrame) -> list:
    """Clean and convert CICIDS2017 DataFrame to MongoDB-ready documents."""
    df.columns = df.columns.str.strip()

    # Drop NaN/Inf
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=['Label'])
    df[numeric_cols] = df[numeric_cols].fillna(0)

    records = []
    base_time = datetime(2024, 7, 3, 8, 0, 0, tzinfo=timezone.utc)

    for idx, row in df.iterrows():
        label = str(row.get('Label', 'BENIGN')).strip()
        dst_port = int(row.get('Destination Port', 0)) if pd.notna(row.get('Destination Port')) else 0

        # Map port to protocol
        proto = "TCP"
        if dst_port == 53:
            proto = "UDP"
        elif dst_port == 80:
            proto = "HTTP"
        elif dst_port == 443:
            proto = "HTTPS"
        elif dst_port == 22:
            proto = "SSH"
        elif dst_port == 21:
            proto = "FTP"

        src_ip = _gen_ip(INTERNAL_SUBNETS) if label == "BENIGN" else random.choice(EXTERNAL_IPS)
        dst_ip = _gen_ip(INTERNAL_SUBNETS)

        timestamp = base_time + timedelta(seconds=idx * 0.5 + random.random() * 2)

        # Build features dict for ML
        features = {}
        for col in numeric_cols:
            if col in df.columns:
                val = row[col]
                if pd.notna(val) and np.isfinite(val):
                    features[col.replace(' ', '_').replace('/', '_')] = float(val)

        record = {
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "protocol": proto,
            "port": dst_port,
            "duration": float(row.get('Flow Duration', 0)) if pd.notna(row.get('Flow Duration')) else 0,
            "packet_size": int(row.get('Total Fwd Packets', 0) + row.get('Total Backward Packets', 0)) if pd.notna(row.get('Total Fwd Packets')) else 0,
            "flow_bytes_per_sec": float(row.get('Flow Bytes/s', 0)) if pd.notna(row.get('Flow Bytes/s', 0)) and np.isfinite(row.get('Flow Bytes/s', 0)) else 0,
            "label": label,
            "attack_cat": label if label != "BENIGN" else None,
            "dataset_source": "CICIDS2017",
            "timestamp": timestamp.isoformat(),
            "features": features,
        }
        records.append(record)

    return records


# ── UNSW-NB15 Loader ──────────────────────────────────────────────────────

def load_unsw_nb15(sample_size: int = 50000) -> pd.DataFrame:
    """Load UNSW-NB15 training + testing sets."""
    data_dir = Path(settings.UNSW_PATH)

    frames = []
    for fname in ["UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"]:
        fpath = data_dir / fname
        if fpath.exists():
            print(f"[UNSW-NB15] Loading: {fname}")
            df = pd.read_csv(fpath, low_memory=False)
            frames.append(df)
            print(f"    Rows: {len(df)}")

    if not frames:
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)

    # Sample while preserving attack distribution
    if len(combined) > sample_size:
        attack_rows = combined[combined['label'] == 1]
        normal_rows = combined[combined['label'] == 0]
        attack_sample = min(len(attack_rows), sample_size // 2)
        normal_sample = sample_size - attack_sample

        if len(attack_rows) > attack_sample:
            attack_rows = attack_rows.sample(n=attack_sample, random_state=42)
        if len(normal_rows) > normal_sample:
            normal_rows = normal_rows.sample(n=normal_sample, random_state=42)

        combined = pd.concat([attack_rows, normal_rows], ignore_index=True)

    print(f"[UNSW-NB15] Total: {len(combined)} rows")
    return combined


def preprocess_unsw(df: pd.DataFrame) -> list:
    """Clean and convert UNSW-NB15 DataFrame to MongoDB-ready documents."""
    # Drop NaN/Inf
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    df[numeric_cols] = df[numeric_cols].fillna(0)

    proto_map = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "arp": "ARP"}

    records = []
    base_time = datetime(2024, 7, 10, 8, 0, 0, tzinfo=timezone.utc)

    for idx, row in df.iterrows():
        label_val = int(row.get('label', 0))
        attack_cat = str(row.get('attack_cat', '')).strip() if pd.notna(row.get('attack_cat')) else ''
        if not attack_cat or attack_cat.lower() == 'normal' or label_val == 0:
            attack_cat = None
            label = "Normal"
        else:
            label = attack_cat

        proto_raw = str(row.get('proto', 'tcp')).lower().strip()
        proto = proto_map.get(proto_raw, proto_raw.upper())

        sport = int(row.get('sport', 0)) if pd.notna(row.get('sport')) else 0
        dsport = int(row.get('dsport', 0)) if pd.notna(row.get('dsport')) else 0

        src_ip = _gen_ip(INTERNAL_SUBNETS) if label_val == 0 else random.choice(EXTERNAL_IPS)
        dst_ip = _gen_ip(INTERNAL_SUBNETS)

        timestamp = base_time + timedelta(seconds=idx * 0.3 + random.random())

        features = {}
        for col in numeric_cols:
            if col in df.columns and col not in ['id', 'label']:
                val = row[col]
                if pd.notna(val) and np.isfinite(val):
                    features[col.replace(' ', '_')] = float(val)

        record = {
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "protocol": proto,
            "port": dsport,
            "duration": float(row.get('dur', 0)) if pd.notna(row.get('dur')) else 0,
            "packet_size": int(row.get('spkts', 0) + row.get('dpkts', 0)) if pd.notna(row.get('spkts')) else 0,
            "flow_bytes_per_sec": float(row.get('sload', 0)) if pd.notna(row.get('sload', 0)) else 0,
            "label": label,
            "attack_cat": attack_cat,
            "dataset_source": "UNSW-NB15",
            "timestamp": timestamp.isoformat(),
            "features": features,
        }
        records.append(record)

    return records


# ── Alert Generation from Attack Records ──────────────────────────────────

def generate_alerts_from_records(records: list, max_alerts: int = 5000) -> list:
    """Create PostgreSQL alert rows from attack records."""
    attack_records = [r for r in records if r.get("attack_cat")]
    if len(attack_records) > max_alerts:
        attack_records = random.sample(attack_records, max_alerts)

    alerts = []
    for rec in attack_records:
        attack_type = rec["attack_cat"]
        risk_info = calculate_risk_score(
            attack_type=attack_type,
            confidence=random.uniform(0.65, 0.99),
            frequency=random.randint(1, 5),
        )
        alerts.append({
            "source_ip": rec["source_ip"],
            "dest_ip": rec["dest_ip"],
            "protocol": rec["protocol"],
            "port": rec["port"],
            "attack_type": attack_type,
            "risk_score": risk_info["risk_score"],
            "severity": risk_info["severity"],
            "confidence": risk_info["confidence"],
            "dataset_source": rec["dataset_source"],
            "status": random.choice(["open", "open", "open", "investigating", "resolved"]),
        })

    return alerts


# ── Main Loader Function ──────────────────────────────────────────────────

async def load_all_datasets():
    """Full dataset loading pipeline: load → preprocess → insert into DBs."""
    from app.database import get_mongo_db, async_session
    from app.models.user import Alert

    db = get_mongo_db()

    # Check if data already loaded
    existing = await db.traffic_logs.count_documents({})
    if existing > 0:
        print(f"[Loader] Data already loaded ({existing} records). Skipping.")
        return {"status": "already_loaded", "count": existing}

    all_records = []
    all_alerts = []

    # 1. Load CICIDS2017
    print("\n" + "="*60)
    print("LOADING CICIDS2017")
    print("="*60)
    cicids_df = load_cicids2017(sample_per_file=8000)
    if not cicids_df.empty:
        cicids_records = preprocess_cicids(cicids_df)
        cicids_alerts = generate_alerts_from_records(cicids_records, max_alerts=2500)
        all_records.extend(cicids_records)
        all_alerts.extend(cicids_alerts)
        print(f"[CICIDS2017] Processed: {len(cicids_records)} traffic records, {len(cicids_alerts)} alerts")

    # 2. Load UNSW-NB15
    print("\n" + "="*60)
    print("LOADING UNSW-NB15")
    print("="*60)
    unsw_df = load_unsw_nb15(sample_size=50000)
    if not unsw_df.empty:
        unsw_records = preprocess_unsw(unsw_df)
        unsw_alerts = generate_alerts_from_records(unsw_records, max_alerts=2500)
        all_records.extend(unsw_records)
        all_alerts.extend(unsw_alerts)
        print(f"[UNSW-NB15] Processed: {len(unsw_records)} traffic records, {len(unsw_alerts)} alerts")

    # 3. Insert into MongoDB (traffic_logs)
    if all_records:
        print(f"\n[MongoDB] Inserting {len(all_records)} traffic records...")
        batch_size = 5000
        for i in range(0, len(all_records), batch_size):
            batch = all_records[i:i + batch_size]
            await db.traffic_logs.insert_many(batch)
            print(f"  Inserted batch {i // batch_size + 1}/{(len(all_records) + batch_size - 1) // batch_size}")

    # 4. Insert alerts into PostgreSQL
    if all_alerts:
        print(f"\n[PostgreSQL] Inserting {len(all_alerts)} alerts...")
        async with async_session() as session:
            for alert_data in all_alerts:
                alert = Alert(**alert_data)
                session.add(alert)
            await session.commit()
            print(f"  Committed {len(all_alerts)} alerts")

    total = len(all_records)
    print(f"\n{'='*60}")
    print(f"DATASET LOADING COMPLETE: {total} traffic records, {len(all_alerts)} alerts")
    print(f"{'='*60}\n")

    return {"status": "loaded", "traffic_records": total, "alerts": len(all_alerts)}
