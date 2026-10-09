import os
import sys

import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.preprocessing import (
    preprocess_dataframe,
    find_label_column,
    clean_column_names,
)
from ml.evaluation import evaluate_predictions


def train_network_anomaly_model(dataset_path=None):
    """
    NetShield AI Random Forest Machine Learning Pipeline.

    The production ML model is:
        - Random Forest Classifier (Scikit-Learn)

    The trained artifacts are:
        - network_model.pkl
        - label_encoder.pkl
        - feature_names.pkl
        - all_models_evaluation.pkl

    The same Random Forest model is used by the FastAPI backend
    for network anomaly and attack classification.
    """

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    models_dir = os.path.join(base_dir, "models")
    os.makedirs(models_dir, exist_ok=True)

    if dataset_path is None:
        candidate_paths = [
            os.path.join(base_dir, "dataset", "sample_network_traffic.csv"),
            os.path.join(os.path.dirname(base_dir), "dataset", "sample_network_traffic.csv"),
        ]
        dataset_path = next((p for p in candidate_paths if os.path.exists(p)), candidate_paths[0])

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(
            f"Dataset for training not found at: {dataset_path}"
        )

    print("=" * 70)
    print("NETSHIELD AI - RANDOM FOREST MODEL TRAINING")
    print("=" * 70)
    print(f"Loading dataset from: {dataset_path}")

    # ------------------------------------------------------------------
    # 1. Load dataset
    # ------------------------------------------------------------------
    df = pd.read_csv(dataset_path)

    print(f"Original dataset shape: {df.shape}")

    # ------------------------------------------------------------------
    # 2. Clean column names and identify label
    # ------------------------------------------------------------------
    df = clean_column_names(df)

    label_col = find_label_column(df)

    if not label_col:
        raise ValueError(
            "Could not find a valid Label / attack classification column "
            "in the dataset."
        )

    print(f"Detected label column: {label_col}")

    # ------------------------------------------------------------------
    # 3. Prepare labels
    # ------------------------------------------------------------------
    y_raw = df[label_col].astype(str).str.strip()

    # ------------------------------------------------------------------
    # 4. Prepare features
    # ------------------------------------------------------------------
    X_df, _, _ = preprocess_dataframe(df)

    feature_names = list(X_df.columns)

    if X_df.empty:
        raise ValueError("No usable features were found in the dataset.")

    # ------------------------------------------------------------------
    # 5. Encode attack labels
    # ------------------------------------------------------------------
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y_raw)

    classes_list = list(label_encoder.classes_)

    print(f"Prepared samples: {X_df.shape[0]}")
    print(f"Prepared features: {X_df.shape[1]}")
    print(f"Attack classes: {classes_list}")

    # ------------------------------------------------------------------
    # 6. Train / test split
    # ------------------------------------------------------------------
    stratify_value = y_encoded if len(classes_list) > 1 else None

    X_train, X_test, y_train, y_test = train_test_split(
        X_df.values,
        y_encoded,
        test_size=0.20,
        random_state=42,
        stratify=stratify_value,
    )

    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")

    # ------------------------------------------------------------------
    # 7. Initialize Random Forest
    # ------------------------------------------------------------------
    random_forest_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=14,
        random_state=42,
        n_jobs=-1,
    )

    # ------------------------------------------------------------------
    # 8. Train Random Forest
    # ------------------------------------------------------------------
    print("\nTraining Random Forest model...")

    random_forest_model.fit(X_train, y_train)

    print("Random Forest training completed.")

    # ------------------------------------------------------------------
    # 9. Evaluate Random Forest
    # ------------------------------------------------------------------
    y_test_pred_encoded = random_forest_model.predict(X_test)

    y_test_labels = label_encoder.inverse_transform(y_test)
    y_pred_labels = label_encoder.inverse_transform(y_test_pred_encoded)

    metrics = evaluate_predictions(
        y_test_labels,
        y_pred_labels,
    )

    print("\n" + "=" * 70)
    print("RANDOM FOREST EVALUATION")
    print("=" * 70)

    print(f"Accuracy : {metrics['accuracy']}%")
    print(f"Precision: {metrics['precision']}%")
    print(f"Recall   : {metrics['recall']}%")
    print(f"F1 Score : {metrics['f1_score']}%")
    print(f"Correct  : {metrics['correct_predictions']}")
    print(f"Total    : {metrics['total_evaluated']}")

    # ------------------------------------------------------------------
    # 10. Prepare evaluation summary
    # ------------------------------------------------------------------
    all_models_eval = [
        {
            "model_name": "Random Forest Classifier",
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1_score": metrics["f1_score"],
            "correct": metrics["correct_predictions"],
            "total": metrics["total_evaluated"],
        }
    ]

    # ------------------------------------------------------------------
    # 11. Save production model artifacts
    # ------------------------------------------------------------------
    primary_model_path = os.path.join(
        models_dir,
        "network_model.pkl",
    )

    primary_le_path = os.path.join(
        models_dir,
        "label_encoder.pkl",
    )

    primary_feat_path = os.path.join(
        models_dir,
        "feature_names.pkl",
    )

    eval_summary_path = os.path.join(
        models_dir,
        "all_models_evaluation.pkl",
    )

    joblib.dump(
        random_forest_model,
        primary_model_path,
    )

    joblib.dump(
        label_encoder,
        primary_le_path,
    )

    joblib.dump(
        feature_names,
        primary_feat_path,
    )

    joblib.dump(
        all_models_eval,
        eval_summary_path,
    )

    # ------------------------------------------------------------------
    # 12. Final output
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("MODEL ARTIFACTS SAVED")
    print("=" * 70)

    print(f" - network_model.pkl       -> Random Forest")
    print(f" - label_encoder.pkl      -> Attack labels")
    print(f" - feature_names.pkl      -> {len(feature_names)} features")
    print(
        f" - all_models_evaluation.pkl -> "
        f"{len(all_models_eval)} model evaluated"
    )

    print("\n[SUCCESS] Random Forest model training completed.")

    return all_models_eval


if __name__ == "__main__":
    train_network_anomaly_model()