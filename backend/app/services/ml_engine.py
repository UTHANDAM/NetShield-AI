"""
ML Inference Engine — Loads trained .joblib models from Colab and provides prediction API.

Model artifacts (from Uthands/models/):
  - cicids_binary_model.joblib    → Binary anomaly detection (Normal vs Attack)
  - cicids_multiclass_model.joblib → Multi-class threat classification
  - cicids_preprocessor.joblib     → Scaler + label encoders for CICIDS2017
  - unsw_binary_model.joblib       → Binary anomaly detection
  - unsw_multiclass_model.joblib   → Multi-class threat classification  
  - unsw_preprocessor.joblib       → Scaler + label encoders for UNSW-NB15
"""
import joblib
import numpy as np
from pathlib import Path
from typing import Optional, Dict, Any, List
from app.config import settings


class MLEngine:
    """Manages trained XGBoost models and provides inference."""

    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.anomaly_models: Dict[str, Any] = {}
        self.preprocessors: Dict[str, Any] = {}
        self.models_dir = Path(settings.ML_MODELS_DIR)

    def load_models(self):
        """Load all .joblib model and preprocessor files."""
        self.models_dir.mkdir(parents=True, exist_ok=True)

        # Load models
        model_files = {
            "cicids_binary": "cicids_binary_model.joblib",
            "cicids_multiclass": "cicids_multiclass_model.joblib",
            "unsw_binary": "unsw_binary_model.joblib",
            "unsw_multiclass": "unsw_multiclass_model.joblib",
        }

        for key, filename in model_files.items():
            path = self.models_dir / filename
            if path.exists():
                self.models[key] = joblib.load(path)
                print(f"  [ML Engine] Loaded model: {key}")
            else:
                print(f"  [ML Engine] Model not found: {path}")

        for dataset in ("cicids2017", "unsw_nb15"):
            path = self.models_dir / f"isolation_forest_{dataset}.joblib"
            if path.exists():
                self.anomaly_models[dataset] = joblib.load(path)
                print(f"  [ML Engine] Loaded anomaly model: {dataset}")

        # Load preprocessors
        preprocessor_files = {
            "cicids": "cicids_preprocessor.joblib",
            "unsw": "unsw_preprocessor.joblib",
        }

        for key, filename in preprocessor_files.items():
            path = self.models_dir / filename
            if path.exists():
                self.preprocessors[key] = joblib.load(path)
                print(f"  [ML Engine] Loaded preprocessor: {key}")

        print(f"  [ML Engine] Total models loaded: {len(self.models)}, preprocessors: {len(self.preprocessors)}")

    def get_available_models(self) -> List[str]:
        return list(self.models.keys())

    def get_preprocessor_key(self, dataset: str) -> str:
        """Map dataset name to preprocessor key."""
        if "cicids" in dataset.lower():
            return "cicids"
        return "unsw"

    def get_model_key(self, dataset: str, model_type: str = "binary") -> str:
        """Build model lookup key."""
        prefix = "cicids" if "cicids" in dataset.lower() else "unsw"
        return f"{prefix}_{model_type}"

    def get_attack_categories(self, dataset: str) -> List[str]:
        """Get the attack category names from the preprocessor."""
        key = self.get_preprocessor_key(dataset)
        if key in self.preprocessors:
            return self.preprocessors[key].get("attack_categories", [])
        return []

    def get_feature_columns(self, dataset: str) -> List[str]:
        """Get the numeric feature column names from preprocessor."""
        key = self.get_preprocessor_key(dataset)
        if key in self.preprocessors:
            return self.preprocessors[key].get("numeric_cols", [])
        return []

    def predict(self, features: dict, dataset: str = "cicids2017",
                model_type: str = "binary") -> dict:
        """
        Run inference on a single traffic event.
        Returns: attack_type, confidence, risk_score, severity, is_anomaly
        """
        model_key = self.get_model_key(dataset, model_type)

        if model_key not in self.models:
            return {
                "error": f"Model '{model_key}' not found. Available: {list(self.models.keys())}",
                "attack_type": "Unknown",
                "confidence": 0.0,
                "risk_score": 0,
                "severity": "LOW",
                "is_anomaly": False,
            }

        model = self.models[model_key]
        prep_key = self.get_preprocessor_key(dataset)
        preprocessor = self.preprocessors.get(prep_key, {})

        # Determine expected features
        booster_feature_names = getattr(model, "feature_names_in_", None)
        if booster_feature_names is None:
            try:
                booster_feature_names = model.get_booster().feature_names
            except Exception:
                booster_feature_names = None

        if prep_key == "unsw":
            # UNSW expected feature order
            expected_cols = booster_feature_names if booster_feature_names is not None else [
                'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate',
                'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit',
                'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean',
                'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl',
                'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
                'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst',
                'is_sm_ips_ports'
            ]
            label_encoders = preprocessor.get("label_encoders", {})
            cat_cols = preprocessor.get("categorical_cols", ["proto", "service", "state"])

            feature_vector = []
            for col in expected_cols:
                raw_val = features.get(col, 0)
                if col in cat_cols and col in label_encoders:
                    le = label_encoders[col]
                    val_str = str(raw_val).strip()
                    try:
                        if hasattr(le, "classes_") and val_str in le.classes_:
                            val = float(le.transform([val_str])[0])
                        else:
                            val = 0.0
                    except Exception:
                        val = 0.0
                else:
                    try:
                        val = float(raw_val)
                        if not np.isfinite(val):
                            val = 0.0
                    except (ValueError, TypeError):
                        val = 0.0
                feature_vector.append(val)

            X = np.array([feature_vector], dtype=np.float32)

        else:
            # CICIDS2017 feature mapping (70 continuous features)
            expected_cols = booster_feature_names if booster_feature_names is not None else preprocessor.get("numeric_cols", list(features.keys()))

            feature_vector = []
            for col in expected_cols:
                raw_val = features.get(col, 0.0)
                try:
                    val = float(raw_val)
                    if not np.isfinite(val):
                        val = 0.0
                except (ValueError, TypeError):
                    val = 0.0
                feature_vector.append(val)

            X = np.array([feature_vector], dtype=np.float32)

            # Apply scaler for continuous features
            scaler_mean = preprocessor.get("scaler_mean")
            scaler_scale = preprocessor.get("scaler_scale")
            if scaler_mean is not None and scaler_scale is not None:
                try:
                    if len(scaler_mean) == X.shape[1]:
                        X = (X - scaler_mean) / (scaler_scale + 1e-8)
                        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
                except Exception:
                    pass

        # Predict
        try:
            prediction = int(model.predict(X)[0])
        except Exception as e:
            print(f"[ML Engine] Prediction error: {e}")
            prediction = 0

        # Get confidence via predict_proba
        confidence = 0.85
        try:
            proba = model.predict_proba(X)[0]
            confidence = float(np.max(proba))
        except Exception:
            pass

        # Decode label
        if model_type == "binary":
            is_anomaly = bool(prediction == 1)
            attack_type = "Attack" if is_anomaly else "Normal"
        else:
            # Multiclass
            categories = preprocessor.get("attack_categories", [])
            if 0 <= prediction < len(categories):
                attack_type = categories[prediction]
            else:
                attack_type = f"Class_{prediction}"
            is_anomaly = bool(attack_type.lower() not in ("normal", "benign"))

        # Isolation Forest augments supervised classification when a matching
        # artefact has been trained. Missing artefacts degrade gracefully.
        anomaly_score = 0.0
        isolation_model = self.anomaly_models.get(dataset)
        if isolation_model is not None:
            try:
                decision = float(isolation_model.decision_function(X)[0])
                anomaly_score = round(float(1 / (1 + np.exp(decision * 5))), 4)
                is_anomaly = is_anomaly or bool(isolation_model.predict(X)[0] == -1)
            except Exception as exc:
                print(f"[ML Engine] Isolation Forest error: {exc}")
        combined_confidence = max(confidence, anomaly_score)
        risk_info = calculate_risk(combined_confidence, is_anomaly, attack_type)

        return {
            "attack_type": attack_type,
            "confidence": round(combined_confidence, 4),
            "anomaly_score": anomaly_score,
            "risk_score": risk_info["risk_score"],
            "severity": risk_info["severity"],
            "is_anomaly": is_anomaly,
        }

    def predict_batch(self, records: list, dataset: str = "cicids2017",
                      model_type: str = "binary") -> list:
        """Run inference on a batch of traffic records."""
        results = []
        for record in records:
            features = record.get("features", record)
            result = self.predict(features, dataset, model_type)
            result["source_ip"] = record.get("source_ip", "")
            result["dest_ip"] = record.get("dest_ip", "")
            result["protocol"] = record.get("protocol", "")
            results.append(result)
        return results


def calculate_risk(confidence: float, is_anomaly: bool, attack_type: str) -> dict:
    """
    Risk scoring engine matching the Colab notebook's logic:
      P < 0.3 → Low
      0.3 ≤ P < 0.6 → Medium
      0.6 ≤ P < 0.85 → High
      P ≥ 0.85 → Critical
    """
    if not is_anomaly:
        return {"risk_score": 5, "severity": "LOW"}

    # Use anomaly probability for risk tiers
    prob = confidence

    if prob < 0.3:
        severity = "LOW"
        score = int(prob * 100)
    elif prob < 0.6:
        severity = "MEDIUM"
        score = int(30 + (prob - 0.3) * 100)
    elif prob < 0.85:
        severity = "HIGH"
        score = int(60 + (prob - 0.6) * 80)
    else:
        severity = "CRITICAL"
        score = int(85 + (prob - 0.85) * 100)

    # Boost score for known dangerous attack types
    high_risk_types = {"ddos", "dos", "exploits", "backdoor", "shellcode", "worms"}
    if attack_type.lower() in high_risk_types:
        score = min(100, score + 10)

    return {"risk_score": min(100, max(0, score)), "severity": severity}


# Singleton instance
ml_engine = MLEngine()
