import os
import sys
import json
import glob
import time
import joblib
from typing import Tuple, List, Dict
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support

# Ensure workspace is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.config import DATA_CSV_DIR, DATA_ARCHIVE_DIR, MODELS_DIR, CATEGORY_MAP
from src.models.feature_pipeline import (
    KEY_FEATURES,
    ATTACK_CLASSES,
    LABEL_TO_IDX,
    IDX_TO_LABEL,
    clean_and_normalize_flow
)

# True Ground-Truth Label Mapping from CIC-IDS2017
LABEL_MAPPING = {
    'benign': 'Benign',
    'dos hulk': 'DoS',
    'ddos': 'DDoS',
    'dos goldeneye': 'DoS',
    'ftp-patator': 'Brute Force',
    'dos slowloris': 'DoS',
    'dos slowhttptest': 'DoS',
    'ssh-patator': 'Brute Force',
    'portscan': 'Port Scan',
    'web attack – brute force': 'Web Attacks',
    'web attack - brute force': 'Web Attacks',
    'bot': 'Botnet',
    'web attack – xss': 'Web Attacks',
    'web attack - xss': 'Web Attacks',
    'infiltration': 'Infiltration',
    'web attack – sql injection': 'Web Attacks',
    'web attack - sql injection': 'Web Attacks',
    'heartbleed': 'DoS'
}

def map_raw_label(raw_val: str) -> str:
    cleaned = str(raw_val).lower().replace('\ufffd', '-').strip()
    for k, v in LABEL_MAPPING.items():
        if k in cleaned:
            return v
    return 'Benign'

def load_balanced_dataset(samples_per_category: int = 15000) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
    """
    Loads balanced data slices across all 8 attack profiles using the true ground truth 'Label' column.
    """
    print(f"[INFO] Sampling dataset from {DATA_CSV_DIR} using true ground-truth labels...")
    
    csv_files = sorted(glob.glob(str(DATA_CSV_DIR / "*.csv")))
    is_parquet = False
    if not csv_files:
        csv_files = sorted(glob.glob(str(DATA_ARCHIVE_DIR / "*.parquet")))
        is_parquet = True

    dfs = []
    for fpath in csv_files:
        fname = os.path.basename(fpath)
        print(f"  -> Reading {fname}...")
        if is_parquet:
            df_slice = pd.read_parquet(fpath)
        else:
            df_slice = pd.read_csv(fpath, low_memory=False)
            
        if 'Label' in df_slice.columns:
            df_slice['true_category'] = df_slice['Label'].apply(map_raw_label)
        else:
            df_slice['true_category'] = 'Benign'
            
        dfs.append(df_slice)

    combined_all = pd.concat(dfs, ignore_index=True)
    print(f"\n[INFO] Ground-truth class distribution across loaded records:")
    print(combined_all['true_category'].value_counts())
    
    # Stratified/Balanced sample per true category
    balanced_dfs = []
    for cat in ATTACK_CLASSES:
        cat_subset = combined_all[combined_all['true_category'] == cat]
        n_avail = len(cat_subset)
        if n_avail == 0:
            continue
        n_take = min(samples_per_category, n_avail)
        balanced_dfs.append(cat_subset.sample(n=n_take, random_state=42))
        print(f"  -> Category '{cat}': sampled {n_take:,d} / {n_avail:,d} available")

    combined = pd.concat(balanced_dfs, ignore_index=True)
    print(f"\n[INFO] Total Balanced Training Pool: {len(combined):,d} records")
    
    available_features = [col for col in KEY_FEATURES if col in combined.columns]
    X_raw = combined[available_features]
    y = combined['true_category']
    
    X_cleaned = clean_and_normalize_flow(X_raw, feature_cols=available_features)
    return X_cleaned, y, available_features

def train_and_evaluate():
    start_time = time.time()
    X, y, feature_cols = load_balanced_dataset(samples_per_category=15000)
    
    y_encoded = y.map(LABEL_TO_IDX).fillna(0).astype(int)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.20, random_state=42, stratify=y_encoded
    )
    
    print(f"[INFO] Training set: {len(X_train):,d} samples | Test set: {len(X_test):,d} samples")
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("[INFO] Training HistGradientBoostingClassifier (optimized for high-throughput stream inference)...")
    clf = HistGradientBoostingClassifier(
        max_iter=150,
        learning_rate=0.08,
        max_depth=12,
        min_samples_leaf=30,
        random_state=42,
        class_weight='balanced'
    )
    
    fit_start = time.time()
    clf.fit(X_train_scaled, y_train)
    fit_duration = time.time() - fit_start
    print(f"[INFO] Model trained successfully in {fit_duration:.2f} seconds!")
    
    # Evaluate
    print("[INFO] Evaluating model on unseen holdout test set...")
    y_pred = clf.predict(X_test_scaled)
    y_prob = clf.predict_proba(X_test_scaled)
    
    acc = accuracy_score(y_test, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
    
    # Per-class report
    target_names = [IDX_TO_LABEL[i] for i in sorted(IDX_TO_LABEL.keys()) if i in np.unique(y_test)]
    report_dict = classification_report(y_test, y_pred, target_names=target_names, output_dict=True)
    report_text = classification_report(y_test, y_pred, target_names=target_names)
    
    print("\n" + "="*65)
    print("MODEL EVALUATION RESULTS ON CIC-IDS2017 HOLDOUT TEST SET")
    print("="*65)
    print(f"Overall Accuracy:  {acc * 100:.2f}%")
    print(f"Weighted Precision: {prec * 100:.2f}%")
    print(f"Weighted Recall:    {rec * 100:.2f}%")
    print(f"Weighted F1-Score:  {f1 * 100:.2f}%\n")
    print(report_text)
    
    # Save artifacts
    model_path = MODELS_DIR / "threat_detector.joblib"
    scaler_path = MODELS_DIR / "scaler.joblib"
    cols_path = MODELS_DIR / "feature_columns.json"
    metrics_path = MODELS_DIR / "evaluation_metrics.json"
    
    joblib.dump(clf, model_path)
    joblib.dump(scaler, scaler_path)
    
    with open(cols_path, 'w') as f:
        json.dump(feature_cols, f, indent=2)
        
    metrics_summary = {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1),
        "training_duration_seconds": float(fit_duration),
        "num_features": len(feature_cols),
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "classes": ATTACK_CLASSES,
        "classification_report": report_dict
    }
    with open(metrics_path, 'w') as f:
        json.dump(metrics_summary, f, indent=2)
        
    print(f"[INFO] Saved model to: {model_path}")
    print(f"[INFO] Saved scaler to: {scaler_path}")
    print(f"[INFO] Saved metrics to: {metrics_path}")
    print(f"[INFO] Total execution time: {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    train_and_evaluate()
