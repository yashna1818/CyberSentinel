import os
import glob
import time
import uuid
import random
import logging
import threading
import pandas as pd
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

from src.config import (
    DATA_CSV_DIR,
    DATA_ARCHIVE_DIR,
    CATEGORY_MAP,
    CIC_IDS2017_TOPOLOGY,
    ATTACK_PORT_MAP,
    TOPIC_SECURITY_LOGS
)
from src.streaming.bus import stream_bus

logger = logging.getLogger("StreamProducer")

class DatasetStreamProducer:
    """
    Simulates real-time network flow telemetry by replaying the preprocessed CIC-IDS2017 dataset.
    Enriches statistical flow records with dynamic timestamps, enterprise IP topology, and ports.
    """
    def __init__(self, target_eps: float = 50.0):
        self.target_eps = target_eps
        self.is_running = False
        self.is_paused = False
        self._thread: Optional[threading.Thread] = None
        self._data_pool: List[Dict[str, Any]] = []
        self._cursor = 0
        self._load_dataset_pool()

    def _load_dataset_pool(self, samples_per_file: int = 5000):
        """Pre-loads diverse samples across all 8 attack profiles into memory for zero-disk-latency replay"""
        logger.info(f"Preloading stream replay buffer from {DATA_CSV_DIR}...")
        csv_files = sorted(glob.glob(str(DATA_CSV_DIR / "*.csv")))
        is_parquet = False
        if not csv_files:
            csv_files = sorted(glob.glob(str(DATA_ARCHIVE_DIR / "*.parquet")))
            is_parquet = True

        combined_records = []
        for fpath in csv_files:
            fname = os.path.basename(fpath)
            cat = CATEGORY_MAP.get(fname, "Benign")
            try:
                if is_parquet:
                    df = pd.read_parquet(fpath)
                else:
                    df = pd.read_csv(fpath, low_memory=False)
                
                # Sample
                n = min(samples_per_file, len(df))
                sampled = df.sample(n=n, random_state=42)
                sampled['category'] = cat
                
                # Clean label
                if 'Label' in sampled.columns:
                    sampled['ground_truth_label'] = sampled['Label'].astype(str).str.replace('\ufffd', '–').str.strip()
                else:
                    sampled['ground_truth_label'] = cat
                    
                records = sampled.to_dict(orient='records')
                combined_records.extend(records)
            except Exception as e:
                logger.error(f"Error loading {fname}: {e}")

        # Shuffle pool to simulate real-world interleaved network traffic
        random.seed(42)
        random.shuffle(combined_records)
        self._data_pool = combined_records
        logger.info(f"Loaded {len(self._data_pool):,d} records into streaming buffer.")

    def _synthesize_network_metadata(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synthesizes realistic network topology metadata (IPs, ports, timestamps)
        consistent with the authentic CIC-IDS2017 environment.
        """
        cat = record.get("category", "Benign")
        ground_truth = str(record.get("ground_truth_label", "Benign"))
        is_actual_attack = (ground_truth != "Benign" and "benign" not in ground_truth.lower())
        
        # Protocol
        raw_proto = record.get("Protocol", 6)
        try:
            proto = int(raw_proto)
        except (ValueError, TypeError):
            proto = 6

        # Source & Destination IP allocation
        if is_actual_attack:
            if "Infiltration" in cat:
                # Lateral movement: Internal workstation attacking peer
                src_ip = CIC_IDS2017_TOPOLOGY["lateral_infiltrator"]
                dst_ip = random.choice(["192.168.10.14", "192.168.10.15", "192.168.10.25"])
            elif "Botnet" in cat:
                # Botnet internal zombie communicating with C2 or vice-versa
                src_ip = random.choice(CIC_IDS2017_TOPOLOGY["victim_workstations"])
                dst_ip = CIC_IDS2017_TOPOLOGY["botnet_c2_master"]
            elif "DDoS" in cat:
                # Distributed sources from attacker subnet
                src_ip = f"{CIC_IDS2017_TOPOLOGY['external_attacker_ddos_subnet']}{random.randint(10, 250)}"
                dst_ip = CIC_IDS2017_TOPOLOGY["victim_web_server"]
            elif "Brute Force" in cat:
                src_ip = CIC_IDS2017_TOPOLOGY["external_attacker_main"]
                dst_ip = CIC_IDS2017_TOPOLOGY["victim_ubuntu_ssh"] if "SSH" in ground_truth else CIC_IDS2017_TOPOLOGY["victim_windows_ftp"]
            elif "Port Scan" in cat:
                src_ip = CIC_IDS2017_TOPOLOGY["external_attacker_main"]
                dst_ip = random.choice([CIC_IDS2017_TOPOLOGY["victim_web_server"], CIC_IDS2017_TOPOLOGY["victim_ubuntu_ssh"]])
            else: # DoS / Web Attacks
                src_ip = CIC_IDS2017_TOPOLOGY["external_attacker_main"]
                dst_ip = CIC_IDS2017_TOPOLOGY["victim_web_server"]
        else:
            # Benign background enterprise traffic
            if random.random() < 0.7:
                # Internal client reaching external internet service
                src_ip = random.choice(CIC_IDS2017_TOPOLOGY["victim_workstations"])
                dst_ip = random.choice(CIC_IDS2017_TOPOLOGY["external_benign_web"] + CIC_IDS2017_TOPOLOGY["dns_servers"])
            else:
                # Internal client reaching internal server
                src_ip = random.choice(CIC_IDS2017_TOPOLOGY["victim_workstations"])
                dst_ip = random.choice([
                    CIC_IDS2017_TOPOLOGY["victim_web_server"],
                    CIC_IDS2017_TOPOLOGY["victim_ubuntu_ssh"],
                    CIC_IDS2017_TOPOLOGY["victim_windows_ftp"]
                ])

        # Destination Port
        if is_actual_attack and cat in ATTACK_PORT_MAP:
            dst_port = random.choice(ATTACK_PORT_MAP[cat])
        elif proto == 17: # UDP (often DNS)
            dst_port = 53
        elif dst_ip in CIC_IDS2017_TOPOLOGY["external_benign_web"] or dst_ip == CIC_IDS2017_TOPOLOGY["victim_web_server"]:
            dst_port = random.choice([80, 443])
        elif dst_ip == CIC_IDS2017_TOPOLOGY["victim_ubuntu_ssh"]:
            dst_port = 22
        elif dst_ip == CIC_IDS2017_TOPOLOGY["victim_windows_ftp"]:
            dst_port = 21
        else:
            dst_port = random.choice([80, 443, 8080, 445, 53])

        src_port = random.randint(49152, 65535)

        event = dict(record)
        event["event_id"] = str(uuid.uuid4())
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        event["src_ip"] = src_ip
        event["dst_ip"] = dst_ip
        event["src_port"] = src_port
        event["dst_port"] = dst_port
        event["protocol"] = proto
        event["is_attack"] = is_actual_attack
        return event

    def start(self):
        """Starts real-time streaming replay in a dedicated background thread"""
        if self.is_running:
            return
        self.is_running = True
        self.is_paused = False
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="DatasetStreamProducerThread")
        self._thread.start()
        logger.info(f"Stream producer started at {self.target_eps} EPS.")

    def pause(self):
        self.is_paused = True

    def resume(self):
        self.is_paused = False

    def stop(self):
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    def set_speed(self, eps: float):
        """Dynamically updates publishing rate in events/second"""
        self.target_eps = max(1.0, float(eps))
        logger.info(f"Publishing rate set to {self.target_eps} EPS.")

    def _run_loop(self):
        n_events = len(self._data_pool)
        if n_events == 0:
            logger.error("No dataset events available to stream!")
            return

        while self.is_running:
            if self.is_paused:
                time.sleep(0.1)
                continue

            batch_size = max(1, int(self.target_eps / 10))
            sleep_interval = 0.1 # 100ms cycles
            
            for _ in range(batch_size):
                if not self.is_running:
                    break
                raw_record = self._data_pool[self._cursor]
                self._cursor = (self._cursor + 1) % n_events
                
                event = self._synthesize_network_metadata(raw_record)
                stream_bus.produce(
                    topic=TOPIC_SECURITY_LOGS,
                    value=event,
                    key=event["src_ip"]
                )

            time.sleep(sleep_interval)

# Global producer instance
stream_producer = DatasetStreamProducer()
