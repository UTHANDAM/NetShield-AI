"""
NetShield AI — Model Training Script (Random Forest + XGBoost)
Trains supervised classification models on CICIDS2017 & UNSW-NB15 datasets.
Computes Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix, and saves .pkl artifacts.
"""

import os
import json
import time
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

OUTPUT_DIR = Path(__file__).parent / "models"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CICIDS_PATH = r"C:\Users\UTHANDAM\Desktop\netshield ai\DATASET\CICIDS2017"
UNSW_PATH = r"C:\Users\UTHANDAM\Desktop\netshield ai\DATASET\UNSW-NB15 datasets"


def train_and_evaluate(X_train, X_test, y_train, y_test, model_name, dataset_name, label_encoder):
    print(f"\n--- Training {model_name} on {dataset_name} ---")
    start_time = time.time()

    if model_name == "random_forest":
        clf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
    elif model_name == "xgboost":
        clf = XGBClassifier(n_estimators=100, max_depth=10, learning_rate=0.1, random_state=42, n_jobs=-1)
    else:
        raise ValueError(f"Unknown model name: {model_name}")

    clf.fit(X_train, y_train)
    training_time_ms = int((time.time() - start_time) * 1000)

    y_pred = clf.predict(X_test)

    # Probabilities for ROC-AUC
    try:
        y_proba = clf.predict_proba(X_test)
        if len(np.unique(y_test)) == 2:
            roc_auc = float(roc_auc_score(y_test, y_proba[:, 1]))
        else:
            roc_auc = float(roc_auc_score(y_test, y_proba, multi_class='ovr', average='weighted'))
    except Exception as e:
        roc_auc = 0.0

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average='weighted', zero_division=0))
    rec = float(recall_score(y_test, y_pred, average='weighted', zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average='weighted', zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    # Feature importances
    if hasattr(clf, "feature_importances_"):
        fi = clf.feature_importances_.tolist()
    else:
        fi = []

    metrics = {
        "model_name": model_name,
        "dataset": dataset_name,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "roc_auc": roc_auc,
        "training_time_ms": training_time_ms,
        "confusion_matrix": cm,
        "per_class_metrics": report,
        "feature_importances": fi,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    # Save artifacts
    model_filename = OUTPUT_DIR / f"{model_name}_{dataset_name}.pkl"
    metrics_filename = OUTPUT_DIR / f"{model_name}_{dataset_name}_metrics.json"

    joblib.dump(clf, model_filename)
    with open(metrics_filename, 'w') as f:
        json.dump(metrics, f, indent=2)

    print(f"Artifacts saved to {model_filename}")
    print(f"Accuracy: {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f} | ROC-AUC: {roc_auc:.4f}")
    return metrics


def train_isolation_forest(X_train, X_test, dataset_name):
    """Train the unsupervised half of the detection pipeline and store its artifact."""
    start_time = time.time()
    model = IsolationForest(n_estimators=150, contamination=0.05, random_state=42, n_jobs=-1)
    model.fit(X_train)
    joblib.dump(model, OUTPUT_DIR / f"isolation_forest_{dataset_name}.joblib")
    return {"model_name": "isolation_forest", "dataset": dataset_name, "training_time_ms": int((time.time() - start_time) * 1000), "sample_size": len(X_test)}


def train_cicids2017():
    print("Loading CICIDS2017 dataset for training...")
    data_dir = Path(CICIDS_PATH)
    csv_files = list(data_dir.glob("*.csv"))

    if not csv_files:
        print("No CICIDS2017 CSV files found!")
        return

    frames = []
    for f in csv_files[:3]:  # Train on subset for local speed
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        frames.append(df)

    df = pd.concat(frames, ignore_index=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    X = df.drop(columns=['Label'])
    X = X.select_dtypes(include=[np.number])
    y = df['Label']

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    joblib.dump(scaler, OUTPUT_DIR / "scaler_cicids2017.pkl")
    joblib.dump(le, OUTPUT_DIR / "label_encoder_cicids2017.pkl")

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_encoded, random_state=42, test_size=0.2, stratify=y_encoded)

    train_and_evaluate(X_train, X_test, y_train, y_test, "random_forest", "cicids2017", le)
    train_and_evaluate(X_train, X_test, y_train, y_test, "xgboost", "cicids2017", le)
    train_isolation_forest(X_train, X_test, "cicids2017")


def train_unsw_nb15():
    print("Loading UNSW-NB15 dataset for training...")
    data_dir = Path(UNSW_PATH)
    train_file = data_dir / "UNSW_NB15_training-set.csv"
    test_file = data_dir / "UNSW_NB15_testing-set.csv"

    if not train_file.exists():
        print("UNSW-NB15 training file not found!")
        return

    df_train = pd.read_csv(train_file)
    df_test = pd.read_csv(test_file) if test_file.exists() else df_train.sample(frac=0.2)

    df = pd.concat([df_train, df_test], ignore_index=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    y = df['attack_cat'].fillna('Normal').astype(str)
    X = df.drop(columns=['id', 'label', 'attack_cat', 'proto', 'service', 'state'], errors='ignore')
    X = X.select_dtypes(include=[np.number])

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    joblib.dump(scaler, OUTPUT_DIR / "scaler_unsw_nb15.pkl")
    joblib.dump(le, OUTPUT_DIR / "label_encoder_unsw_nb15.pkl")

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_encoded, random_state=42, test_size=0.2, stratify=y_encoded)

    train_and_evaluate(X_train, X_test, y_train, y_test, "random_forest", "unsw_nb15", le)
    train_and_evaluate(X_train, X_test, y_train, y_test, "xgboost", "unsw_nb15", le)
    train_isolation_forest(X_train, X_test, "unsw_nb15")


if __name__ == "__main__":
    train_cicids2017()
    train_unsw_nb15()
