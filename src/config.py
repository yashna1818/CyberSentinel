import os
from pathlib import Path

# Base Paths
WORKSPACE_ROOT = Path(os.path.abspath(__file__)).parent.parent
DATA_CSV_DIR = WORKSPACE_ROOT / "csv"
DATA_ARCHIVE_DIR = Path("/Users/yashna/Downloads/archive")
MODELS_DIR = WORKSPACE_ROOT / "models"
KNOWLEDGE_BASE_DIR = WORKSPACE_ROOT / "knowledge_base"
SRC_DIR = WORKSPACE_ROOT / "src"

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(KNOWLEDGE_BASE_DIR, exist_ok=True)

# Dataset file-to-category mapping (Identical to Phase 1 EDA)
CATEGORY_MAP = {
    'Benign-Monday-no-metadata.parquet': 'Benign',
    'Bruteforce-Tuesday-no-metadata.parquet': 'Brute Force',
    'DoS-Wednesday-no-metadata.parquet': 'DoS',
    'Infiltration-Thursday-no-metadata.parquet': 'Infiltration',
    'WebAttacks-Thursday-no-metadata.parquet': 'Web Attacks',
    'Botnet-Friday-no-metadata.parquet': 'Botnet',
    'DDoS-Friday-no-metadata.parquet': 'DDoS',
    'Portscan-Friday-no-metadata.parquet': 'Port Scan',
    'Benign-Monday-no-metadata.csv': 'Benign',
    'Bruteforce-Tuesday-no-metadata.csv': 'Brute Force',
    'DoS-Wednesday-no-metadata.csv': 'DoS',
    'Infiltration-Thursday-no-metadata.csv': 'Infiltration',
    'WebAttacks-Thursday-no-metadata.csv': 'Web Attacks',
    'Botnet-Friday-no-metadata.csv': 'Botnet',
    'DDoS-Friday-no-metadata.csv': 'DDoS',
    'Portscan-Friday-no-metadata.csv': 'Port Scan'
}

# Real-world CIC-IDS2017 Network Topology for realistic stream enrichment
CIC_IDS2017_TOPOLOGY = {
    "victim_web_server": "192.168.10.50",
    "victim_ubuntu_ssh": "192.168.10.51",
    "victim_windows_ftp": "192.168.10.14",
    "victim_workstations": ["192.168.10.3", "192.168.10.8", "192.168.10.9", "192.168.10.12", "192.168.10.15", "192.168.10.25"],
    "external_attacker_main": "205.174.165.73",
    "external_attacker_ddos_subnet": "205.174.165.",
    "botnet_c2_master": "205.174.165.80",
    "lateral_infiltrator": "192.168.10.8",
    "dns_servers": ["8.8.8.8", "1.1.1.1", "192.168.10.1"],
    "external_benign_web": ["172.217.16.206", "151.101.1.140", "13.107.4.50", "104.244.42.1"]
}

# Attack target port defaults
ATTACK_PORT_MAP = {
    "Brute Force": [21, 22],        # FTP-Patator (21), SSH-Patator (22)
    "DoS": [80, 443, 8080],        # HTTP Slowloris, Slowhttptest, Hulk, GoldenEye
    "DDoS": [80, 443],             # Volumetric web flood
    "Web Attacks": [80, 8080],      # SQLi, XSS, Brute force web
    "Infiltration": [445, 139, 22], # Exploitation & lateral movement
    "Botnet": [8080, 6667, 443],   # ARES Botnet C2
    "Port Scan": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 8080]
}

# Streaming & Kafka Topics Configuration
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC_SECURITY_LOGS = "security-logs"
TOPIC_DETECTED_THREATS = "detected-threats"
TOPIC_SECURITY_ALERTS = "security-alerts"

# Windowing parameters
DEFAULT_WINDOW_SIZE_SECONDS = 10.0
DEFAULT_SLIDE_INTERVAL_SECONDS = 2.0
LATE_ARRIVAL_TOLERANCE_SECONDS = 5.0

# API & Dashboard
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
WS_URL = f"ws://{API_HOST}:{API_PORT}/ws/stream"
