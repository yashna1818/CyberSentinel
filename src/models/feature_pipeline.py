import numpy as np
import pandas as pd
from typing import List, Tuple

# Key discriminative features identified in Phase 1 EDA
KEY_FEATURES = [
    'Protocol',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Fwd Packets Length Total',
    'Bwd Packets Length Total',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Std',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd IAT Total',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Fwd IAT Max',
    'Fwd IAT Min',
    'Bwd IAT Total',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    'Bwd IAT Max',
    'Bwd IAT Min',
    'Fwd PSH Flags',
    'Bwd PSH Flags',
    'Fwd URG Flags',
    'Bwd URG Flags',
    'Fwd Header Length',
    'Bwd Header Length',
    'Fwd Packets/s',
    'Bwd Packets/s',
    'Packet Length Min',
    'Packet Length Max',
    'Packet Length Mean',
    'Packet Length Std',
    'Packet Length Variance',
    'FIN Flag Count',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'URG Flag Count',
    'CWE Flag Count',
    'ECE Flag Count',
    'Down/Up Ratio',
    'Avg Packet Size',
    'Avg Fwd Segment Size',
    'Avg Bwd Segment Size',
    'Init Fwd Win Bytes',
    'Init Bwd Win Bytes',
    'Fwd Act Data Packets',
    'Fwd Seg Size Min',
    'Active Mean',
    'Active Std',
    'Active Max',
    'Active Min',
    'Idle Mean',
    'Idle Std',
    'Idle Max',
    'Idle Min'
]

# Highly skewed metrics that benefit from log1p scaling (as proven in EDA Slide 2)
LOG1P_FEATURES = [
    'Flow Duration',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Max',
    'Fwd IAT Total',
    'Bwd IAT Total',
    'Active Mean',
    'Idle Mean',
    'Packet Length Variance'
]

ATTACK_CLASSES = [
    'Benign',
    'DoS',
    'Brute Force',
    'DDoS',
    'Infiltration',
    'Botnet',
    'Web Attacks',
    'Port Scan'
]

LABEL_TO_IDX = {cat: idx for idx, cat in enumerate(ATTACK_CLASSES)}
IDX_TO_LABEL = {idx: cat for idx, cat in enumerate(ATTACK_CLASSES)}

def clean_and_normalize_flow(df: pd.DataFrame, feature_cols: List[str] = None) -> pd.DataFrame:
    """
    Cleans raw flow records:
    1. Selects numeric features
    2. Replaces inf/-inf with numerical limits
    3. Fills missing values with 0
    4. Applies log1p transformation to skewed metrics
    """
    if feature_cols is None:
        feature_cols = [c for c in KEY_FEATURES if c in df.columns]
    
    cleaned = df[feature_cols].copy()
    
    # Replace inf and -inf with NaNs then fill
    cleaned = cleaned.replace([np.inf, -np.inf], np.nan)
    cleaned = cleaned.fillna(0.0)
    
    # Apply log1p scaling to positive values of heavy-tailed features
    for col in LOG1P_FEATURES:
        if col in cleaned.columns:
            cleaned[col] = np.log1p(np.clip(cleaned[col].values, a_min=0, a_max=None))
            
    return cleaned
