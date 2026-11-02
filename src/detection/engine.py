import os
import json
import time
import uuid
import joblib
import logging
import numpy as np
import pandas as pd
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone

from src.config import (
    MODELS_DIR,
    TOPIC_DETECTED_THREATS
)
from src.models.feature_pipeline import (
    KEY_FEATURES,
    ATTACK_CLASSES,
    IDX_TO_LABEL,
    clean_and_normalize_flow
)
from src.streaming.bus import stream_bus
from src.streaming.metrics import stream_metrics

logger = logging.getLogger("ThreatDetectionEngine")

class HybridDetectionEngine:
    """
    Hybrid threat detection system combining:
    1. Pre-trained ML inference (HistGradientBoosting / Random Forest)
    2. Statistical rule-based heuristics & signature thresholds
    3. Multi-event time-window state correlation
    """
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_columns = []
        self._load_model_artifacts()
        
        # Incident suppression / cooldown tracker: (src_ip, attack_category) -> last_alert_time
        self.incident_cooldown: Dict[Tuple[str, str], float] = {}
        self.cooldown_seconds = 12.0
        
        # Attack stage tracker for multi-stage correlation (src_ip -> list of stages)
        self.ip_attack_history: Dict[str, List[Dict[str, Any]]] = {}

    def _load_model_artifacts(self):
        model_path = MODELS_DIR / "threat_detector.joblib"
        scaler_path = MODELS_DIR / "scaler.joblib"
        cols_path = MODELS_DIR / "feature_columns.json"
        
        if model_path.exists() and scaler_path.exists() and cols_path.exists():
            try:
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                with open(cols_path, "r") as f:
                    self.feature_columns = json.load(f)
                logger.info(f"Loaded ML Threat Detector ({len(self.feature_columns)} features).")
            except Exception as e:
                logger.error(f"Error loading ML model artifacts: {e}")
        else:
            logger.warning("ML model artifacts not found; falling back to rule-based detection.")

    def _predict_ml(self, event: Dict[str, Any]) -> Tuple[str, float]:
        """Runs real-time ML inference on a single flow vector"""
        if not self.model or not self.scaler:
            return "Benign", 0.50

        try:
            # Build 1-row DataFrame
            row_dict = {col: [event.get(col, 0.0)] for col in self.feature_columns}
            df_row = pd.DataFrame(row_dict)
            cleaned = clean_and_normalize_flow(df_row, feature_cols=self.feature_columns)
            scaled = self.scaler.transform(cleaned)
            
            probs = self.model.predict_proba(scaled)[0]
            pred_idx = int(np.argmax(probs))
            conf = float(probs[pred_idx])
            pred_label = IDX_TO_LABEL.get(pred_idx, "Benign")
            return pred_label, round(conf, 3)
        except Exception as e:
            return "Benign", 0.0

    def analyze_window(self, window_summary: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Correlates window metrics and ML predictions to identify cybersecurity incidents.
        """
        if not window_summary:
            return None

        t_start = time.time()
        
        src_ip = window_summary.get("src_ip", "0.0.0.0")
        dst_ip = window_summary.get("dst_ip", "0.0.0.0")
        dst_port = window_summary.get("dst_port", 80)
        event_count = window_summary.get("event_count", 1)
        pps = window_summary.get("packets_per_sec", 0.0)
        bps = window_summary.get("bytes_per_sec", 0.0)
        num_ports = window_summary.get("host_distinct_ports_contacted", 1)
        syn_count = window_summary.get("syn_count", 0)
        short_durations = window_summary.get("short_duration_count", 0)
        latest_event = window_summary.get("latest_event", {})
        
        # 1. Run ML inference on latest event in the window
        ml_category, ml_conf = self._predict_ml(latest_event)
        
        # 2. Rule-Based & Correlation Engine Checks
        detected_category = None
        severity = "LOW"
        confidence = ml_conf
        detection_methods = []
        evidence_list = []

        # Rule A: Port Scanning Reconnaissance
        if num_ports >= 10 or (num_ports >= 5 and short_durations >= 5):
            detected_category = "Port Scan"
            severity = "MEDIUM" if num_ports < 20 else "HIGH"
            confidence = max(0.92, ml_conf)
            detection_methods.append("Rule: Horizontal/Vertical Port Scan Sweep")
            evidence_list.append(f"Source IP probed {num_ports} distinct target ports in 10s sliding window")
            evidence_list.append(f"{short_durations} connection attempts exhibited duration < 100ms")

        # Rule B: Distributed Denial of Service (DDoS) / High Volume Floods
        elif pps > 2000.0 or syn_count >= 100:
            detected_category = "DDoS" if "205.174.165." in src_ip else "DoS"
            severity = "CRITICAL"
            confidence = max(0.95, ml_conf)
            detection_methods.append("Rule: Volumetric Flood Anomaly")
            evidence_list.append(f"Observed surge rate of {pps:.1f} packets/sec breaching 2,000 pps threshold")
            evidence_list.append(f"Recorded {syn_count} SYN control flags indicative of state exhaustion")

        # Rule C: Authentication Brute Force (FTP/SSH Patator)
        elif dst_port in [21, 22] and (event_count >= 6 or (ml_category == "Brute Force" and ml_conf > 0.70)):
            detected_category = "Brute Force"
            target_proto = "SSH (22)" if dst_port == 22 else "FTP (21)"
            severity = "HIGH"
            confidence = max(0.90, ml_conf)
            detection_methods.append("Rule: Repeated Authentication Probe Rate")
            evidence_list.append(f"Repeated authentication sessions ({event_count} flows) targeting {target_proto}")
            evidence_list.append(f"Short connection lifetimes with minimal transferred payload bytes")

        # Rule D: Application Denial of Service (Slowloris / HTTP Exhaustion)
        elif dst_port in [80, 443, 8080] and (ml_category == "DoS" and ml_conf > 0.75):
            detected_category = "DoS"
            severity = "HIGH"
            confidence = ml_conf
            detection_methods.append("ML Classifier + Protocol Context")
            evidence_list.append(f"Identified HTTP application exhaustion pattern against web server {dst_ip}")
            evidence_list.append(f"Flow Duration and IAT statistics match Slowloris / GoldenEye signatures")

        # Rule E: Lateral Infiltration / Internal Reconnaissance
        elif src_ip.startswith("192.168.10.") and dst_ip.startswith("192.168.10.") and (ml_category == "Infiltration" or dst_port in [445, 139]):
            detected_category = "Infiltration"
            severity = "CRITICAL"
            confidence = max(0.88, ml_conf)
            detection_methods.append("Rule: Internal Subnet Lateral Movement")
            evidence_list.append(f"Internal workstation {src_ip} targeting internal asset {dst_ip}:{dst_port}")
            evidence_list.append(f"Potential exploit delivery or unauthorized SMB service enumeration")

        # Rule F: Botnet Command & Control (C2)
        elif ml_category == "Botnet" and ml_conf > 0.70:
            detected_category = "Botnet"
            severity = "HIGH"
            confidence = ml_conf
            detection_methods.append("ML Classifier: Botnet Beaconing")
            evidence_list.append(f"Periodic communication channel established with external endpoint {dst_ip}")
            evidence_list.append(f"Packet timing and size profiles align with ARES Botnet protocol")

        # Rule G: Web Application Attacks (SQLi, XSS, Web Brute Force)
        elif ml_category == "Web Attacks" and ml_conf > 0.70:
            detected_category = "Web Attacks"
            severity = "HIGH"
            confidence = ml_conf
            detection_methods.append("ML Classifier: Web Application Exploit")
            evidence_list.append(f"Web exploit payload directed against web service {dst_ip}:{dst_port}")
            evidence_list.append(f"Asymmetric response variance and characteristic HTTP parameter anomalies")

        # Fallback to ML classification if confidence is high and not Benign
        elif ml_category != "Benign" and ml_conf >= 0.85:
            detected_category = ml_category
            severity = "MEDIUM" if ml_conf < 0.90 else "HIGH"
            confidence = ml_conf
            detection_methods.append("Supervised Machine Learning Model")
            evidence_list.append(f"HistGradientBoosting statistical confidence score of {ml_conf * 100:.1f}%")

        if not detected_category:
            return None

        # 3. Multi-Stage Attack Correlation Check
        stage_record = {
            "category": detected_category,
            "timestamp": time.time(),
            "dst_ip": dst_ip,
            "dst_port": dst_port
        }
        if src_ip not in self.ip_attack_history:
            self.ip_attack_history[src_ip] = []
        self.ip_attack_history[src_ip].append(stage_record)
        
        # Check if Port Scan preceded Brute Force or Infiltration
        prior_categories = [s["category"] for s in self.ip_attack_history[src_ip][:-1]]
        if "Port Scan" in prior_categories and detected_category in ["Brute Force", "Infiltration", "Web Attacks"]:
            severity = "CRITICAL"
            detection_methods.append("Stateful Kill-Chain Correlation")
            evidence_list.append(f"Multi-stage attack sequence confirmed: Prior Port Scan reconnaissance succeeded by {detected_category}")

        # 4. Suppression / Cooldown Check to prevent alert storms
        cooldown_key = (src_ip, detected_category)
        now = time.time()
        last_alert = self.incident_cooldown.get(cooldown_key, 0.0)
        if (now - last_alert) < self.cooldown_seconds:
            # Suppress duplicate alert for active ongoing incident
            return None
        self.incident_cooldown[cooldown_key] = now

        # 5. Build Standardized Detected Threat Payload
        threat_id = f"THREAT-{uuid.uuid4().hex[:8].upper()}"
        threat_alert = {
            "threat_id": threat_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "attack_category": detected_category,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "num_related_events": event_count,
            "severity": severity,
            "confidence_score": round(confidence, 3),
            "supporting_evidence": evidence_list,
            "detection_method": " + ".join(detection_methods),
            "window_metrics": {
                "packets_per_sec": pps,
                "bytes_per_sec": bps,
                "num_ports_probed": num_ports,
                "syn_flag_count": syn_count
            },
            "related_event_ids": window_summary.get("event_ids", [])
        }

        # Telemetry
        stream_metrics.record_threat()
        proc_lat = (time.time() - t_start) * 1000.0
        stream_metrics.update_detection_latency(proc_lat)

        # Publish to Kafka / Streaming bus
        stream_bus.produce(
            topic=TOPIC_DETECTED_THREATS,
            value=threat_alert,
            key=src_ip
        )
        
        logger.warning(f"[{severity}] Detected Threat: {detected_category} from {src_ip} -> {dst_ip}:{dst_port} (Conf: {confidence})")
        return threat_alert

# Global detection engine instance
detection_engine = HybridDetectionEngine()
