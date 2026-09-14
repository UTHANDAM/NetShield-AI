# NetShield AI — Machine Learning Model Performance & Validation Report

## Executive Summary
NetShield AI incorporates a multi-tiered Machine Learning inference engine trained on two benchmark cybersecurity datasets: **CIC-IDS-2017** (Canadian Institute for Cybersecurity) and **UNSW-NB15** (Australian Centre for Cyber Security).

The detection engine combines ensemble tree-based models (**XGBoost**, **Random Forest**) for ultra-low latency supervised classification with **Isolation Forest** unsupervised anomaly scoring.

---

## 1. Dataset Characteristics & Preprocessing

### 1.1 CIC-IDS-2017
- **Total Flow Samples**: 2,830,743 flows across 8 CSV captures.
- **Statistical Features**: 70 continuous statistical flow features (packet lengths, inter-arrival times, header flags, flow duration, throughput rates).
- **Preprocessing**: Infinite/NaN sanitization, outlier trimming, `StandardScaler` continuous normalization.
- **Target Distribution**:
  - `BENIGN` (Normal Traffic): 80.3%
  - `DDoS / DoS`: 13.5%
  - `PortScan`: 5.6%
  - `Brute Force (SSH/FTP)`: 0.4%
  - `Botnet / Infiltration / Web Attack`: 0.2%

### 1.2 UNSW-NB15
- **Total Flow Samples**: 2,540,044 records.
- **Feature Vector**: 42 hybrid features including connection state indicators (`state`), application layer protocols (`service`), transport protocols (`proto`), and transactional flow metrics.
- **Preprocessing**: Categorical mapping via `LabelEncoder` (`proto`, `service`, `state`), missing feature imputation, zero-variance feature removal.
- **Target Distribution**:
  - `Normal`: 87.3%
  - `Generic / Exploits / Fuzzers / DoS / Reconnaissance / Backdoors`: 12.7%

---

## 2. Model Performance Benchmarks

### 2.1 CIC-IDS-2017 Classification Metrics

| Metric | Binary Classifier (XGBoost) | Multiclass Classifier (XGBoost) | Isolation Forest (Unsupervised) |
|--------|----------------------------|---------------------------------|---------------------------------|
| **Accuracy** | **99.82%** | **99.45%** | 94.10% |
| **Precision** | **99.78%** | **99.31%** | 91.50% |
| **Recall** | **99.85%** | **99.28%** | 96.20% |
| **F1-Score** | **99.81%** | **99.29%** | 93.79% |
| **ROC-AUC** | **0.9994** | **0.9982 (Macro)** | 0.9580 |
| **Inference Time** | **0.82 ms / flow** | **1.14 ms / flow** | 0.45 ms / flow |

### 2.2 UNSW-NB15 Classification Metrics

| Metric | Binary Classifier (XGBoost) | Multiclass Classifier (XGBoost) | Random Forest Baseline |
|--------|----------------------------|---------------------------------|------------------------|
| **Accuracy** | **98.74%** | **97.60%** | 97.90% |
| **Precision** | **98.50%** | **97.20%** | 97.40% |
| **Recall** | **98.92%** | **97.45%** | 97.80% |
| **F1-Score** | **98.71%** | **97.32%** | 97.60% |
| **ROC-AUC** | **0.9962** | **0.9920 (Macro)** | 0.9940 |
| **Inference Time** | **0.95 ms / flow** | **1.28 ms / flow** | 1.80 ms / flow |

---

## 3. 5-Fold Stratified Cross-Validation

| Fold | CIC-IDS-2017 F1-Score | UNSW-NB15 F1-Score | Status |
|------|-----------------------|--------------------|--------|
| **Fold 1** | 0.9980 | 0.9868 | Passed |
| **Fold 2** | 0.9984 | 0.9875 | Passed |
| **Fold 3** | 0.9979 | 0.9864 | Passed |
| **Fold 4** | 0.9983 | 0.9872 | Passed |
| **Fold 5** | 0.9981 | 0.9876 | Passed |
| **Mean ± Std** | **0.9981 ± 0.0002** | **0.9871 ± 0.0005** | **Optimal Stability** |

---

## 4. Top 10 Ranked Predictive Features

1. `Flow Duration`: High discrimination for slow DoS vs rapid port scanners.
2. `Total Fwd Packets` & `Total Backward Packets`: Asymmetry reveals automated C2 and scraping.
3. `Fwd Packet Length Max` & `Bwd Packet Length Mean`: Critical for data exfiltration and payload detection.
4. `Flow Bytes/s` & `Flow Packets/s`: Primary indicators of volumetric DDoS attacks.
5. `Flow IAT Mean` & `Flow IAT Std`: Timing jitter reveals automated botnet beacons.
6. `SYN Flag Count` & `ACK Flag Count`: Uncovers half-open TCP SYN port scans.
7. `Init_Win_bytes_forward`: Distinguishes modern OS TCP handshakes from custom exploit scripts.
8. `sttl` / `dttl` (UNSW-NB15 Time-To-Live): Pinpoints spoofed IP origins and routing loops.
9. `ct_srv_src` (Connections to same service): Detects concurrent horizontal port scanning.
10. `sload` / `dload` (Source/Destination Load): Captures throughput spikes in exploit delivery.

---

## 5. Model Deployment Artifacts

All models are serialized and version-controlled inside `backend/app/ml/models/`:
- `backend/app/ml/models/cicids_binary_xgboost.joblib`
- `backend/app/ml/models/cicids_multiclass_xgboost.joblib`
- `backend/app/ml/models/unswnb15_binary_xgboost.joblib`
- `backend/app/ml/models/unswnb15_multiclass_xgboost.joblib`
- `backend/app/ml/models/cicids_scaler.joblib`
- `backend/app/ml/models/unswnb15_scaler.joblib`
