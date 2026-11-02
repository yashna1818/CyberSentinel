# PROJECT IMPLEMENTATION PLAN
## Real-Time Cybersecurity Log Correlation with Multi-Agent AI
### Academic Dual-Focus: Stream Processing and Analytics (SPA) & Agentic AI

---

## 1. Executive Summary & Audit of Existing Repository

An exhaustive inspection of the workspace `/Users/yashna/edaspa` and system environment was conducted:

| Component | Status | Details / Location |
| :--- | :--- | :--- |
| **Dataset (CIC-IDS2017)** | Completed | 8 Parquet files in `/Users/yashna/Downloads/archive` (2.31M rows, 78 features). Converted to CSV in `/Users/yashna/edaspa/csv`. |
| **Exploratory Data Analysis (EDA)** | Completed | `EDA/cybersecurity_eda.py`, `EDA/generate_graphs.py`, `EDA/EDA_Report.md`, `PHASE1_EDA_SUMMARY.md`, 18 publication-quality plots in `EDA/plots/`. |
| **Data Hygiene & Preprocessing** | Identified | Zero missing values, 82,004 duplicate flows, heavy-tail skewness requiring log1p scaling, deterministic feature pruning ($r=1.000$). |
| **ML Models** | Missing | No pre-trained `.pkl`/`.joblib` models existed in the repository. A dedicated multi-class & binary classifier will be trained on the preprocessed dataset. |
| **Stream Processing Engine (SPA)** | Missing | Real-time Kafka producer, consumer, event-time sliding windows, stateful correlation engine, and metric telemetry to be built. |
| **Multi-Agent AI (Agentic AI)** | Missing | 4 specialized agents (Detection, Investigation, Threat Intel RAG, Security Response) orchestrated via LangGraph with tool-calling and human-in-the-loop approval. |
| **SOC Dashboard** | Missing | Modern real-time web SOC dashboard with WebSockets, live telemetry, agent workflow inspection, and incident mitigation management. |

---

## 2. End-to-End System Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │ CIC-IDS2017 Dataset (2.31M Flow Records)     │
                    └──────────────────────┬───────────────────────┘
                                           │ (Parquet / CSV)
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │ Stream Producer & Network Metadata Synthesizer│
                    │ - Configurable speed (10 - 10,000 eps)       │
                    │ - Real-time IAT pacing                       │
                    │ - Enriched IP topology & port assignments    │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │ Kafka Broker / Streaming Event Bus           │
                    │ Topic: `security-logs`                       │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │ Stateful Stream Processing Engine (SPA)      │
                    │ - Event-time sliding/tumbling windows        │
                    │ - Partitioning by (Src IP, Dst IP, Port)     │
                    │ - Stateful multi-event aggregation           │
                    │ - ML Feature Extraction + Scaler             │
                    │ - Consumer Lag & Throughput Telemetry        │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │ Hybrid Threat Detection & Correlation Engine │
                    │ - Rule-based heuristics (DoS, PortScan, etc.)│
                    │ - Trained ML Classifier (RandomForest/GBM)   │
                    │ - Multi-stage kill-chain correlation         │
                    │ - Severity (CRITICAL, HIGH, MEDIUM, LOW)     │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │ Kafka Topic: `detected-threats`              │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ MULTI-AGENT CYBERSECURITY INVESTIGATION PLATFORM (LangGraph)                     │
│                                                                                  │
│   ┌────────────────────────┐         ┌────────────────────────┐                  │
│   │ Agent 1: Threat        │────────▶│ Agent 2: Attack        │                  │
│   │ Detection Agent        │         │ Investigation Agent    │                  │
│   │ (Evaluates & triage)   │         │ (Timeline & correlation│                  │
│   └────────────────────────┘         └───────────┬────────────┘                  │
│                                                  │                               │
│                                                  ▼                               │
│   ┌────────────────────────┐         ┌────────────────────────┐                  │
│   │ Agent 4: Security      │◀────────│ Agent 3: Threat        │                  │
│   │ Response Agent         │         │ Intelligence Agent     │                  │
│   │ (Mitigation & HITL)    │         │ (Local MITRE ATT&CK RAG│                  │
│   └───────────┬────────────┘         └────────────────────────┘                  │
│               │                                                                  │
│               ▼                                                                  │
│   ┌────────────────────────┐                                                     │
│   │ Human-in-the-Loop Gate │ ──[ Analyst Review: Approve / Reject Actions ]      │
│   └────────────────────────┘                                                     │
└──────────────────────────────────────────┬───────────────────────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │ Kafka Topic: `security-alerts`               │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │ Real-Time Security Operations Center (SOC)   │
                    │ Dashboard (FastAPI + WebSockets + Web UI)   │
                    │ - Live Stream Telemetry & Throughput         │
                    │ - Event Stream Table & Threat Timeline       │
                    │ - Multi-Agent Thought & Tool Inspection      │
                    │ - Incident Management & HITL Actions         │
                    └──────────────────────────────────────────────┘
```

---

## 3. Detailed Development Stages

### Stage 1: Machine Learning Model Training & Feature Extraction
- **File:** `src/models/train_detector.py`, `src/models/feature_pipeline.py`
- Train a high-performance multi-class and binary classifier on the 78 network-flow features using balanced sampling from the 8 CIC-IDS2017 profiles.
- Save trained artifacts into `models/threat_detector.joblib` and `models/scaler.joblib`.
- Preserve existing EDA code and report results.

### Stage 2: Stream Processing Architecture (SPA) & Kafka Engine
- **Files:**
  - `src/streaming/config.py`: Stream configurations (topics, window sizes, buffer thresholds).
  - `src/streaming/producer.py`: High-throughput streaming producer replaying dataset records with realistic IP/port synthesis and inter-arrival time simulation.
  - `src/streaming/bus.py`: Dual-mode streaming bus supporting both production Apache Kafka (`confluent-kafka`) and embedded in-memory streaming bus for zero-dependency execution.
  - `src/streaming/window_processor.py`: Stateful sliding and tumbling event-time window processor grouping by `(src_ip, dst_ip, protocol, dst_port)` with late-arrival and duplicate filtering.
  - `src/streaming/metrics.py`: Telemetry collector for events/sec, throughput, latency, lag, and dropped counts.

### Stage 3: Hybrid Threat Detection & Correlation Engine
- **File:** `src/detection/engine.py`
- Hybrid pipeline combining:
  1. Statistical baseline breach detection (SYN flag surges, high packets/s, packet length anomalies).
  2. Rule-based attack signatures (FTP/SSH Patator brute-force thresholds, horizontal/vertical port scans, DoS Slowloris, DDoS floods).
  3. Pre-trained ML inference with confidence scoring.
  4. Multi-event sessionization and correlation across time windows.
- Threat alert structure with unique UUID, severity, confidence, related event IDs, and detection methods.

### Stage 4: Local MITRE ATT&CK Knowledge Base & RAG Engine
- **Files:**
  - `knowledge_base/mitre_attack.json`: Verified tactics, techniques, IDs (T1110, T1046, T1498, T1499, T1190, T1071, etc.), mitigations, and detection guidance.
  - `src/agents/rag.py`: Local vector/BM25 retrieval engine querying MITRE techniques based on attack signatures and evidence.

### Stage 5: Multi-Agent AI Cybersecurity Investigation (LangGraph)
- **Files:**
  - `src/agents/tools.py`: Investigation tools (`fetch_related_events`, `get_ip_reputation_history`, `inspect_event_window`, `query_mitre_attack`, `get_detection_evidence`).
  - `src/agents/threat_detection_agent.py`: Evaluates anomalies and triages suspicious activity.
  - `src/agents/investigation_agent.py`: Reconstructs attack timeline and assesses multi-stage threat progression.
  - `src/agents/threat_intel_agent.py`: Executes RAG queries against local MITRE ATT&CK knowledge base.
  - `src/agents/security_response_agent.py`: Formulates defensive mitigations and packages human-in-the-loop approval payloads.
  - `src/agents/orchestrator.py`: LangGraph StateGraph connecting all 4 agents with memory, guardrails, and fallback to rule-based analysis if LLM is offline.

### Stage 6: Real-Time SOC Dashboard & Backend API
- **Files:**
  - `src/api/server.py`: FastAPI server managing WebSocket streams, REST endpoints for stream control, metrics, incidents, and analyst approvals.
  - `src/dashboard/index.html`: Responsive, dark-mode cybersecurity SOC dashboard.
  - `src/dashboard/styles.css`: Sleek glassmorphism visual styling, cybernetic color palette, and micro-animations.
  - `src/dashboard/app.js`: WebSocket client with live telemetry charts, event logs, agent thought tree, and incident approval workflow.

### Stage 7: Performance Evaluation & Validation Experiments
- **File:** `tests/run_performance_benchmark.py`, `tests/test_pipeline.py`
- Comprehensive test suite testing producer, consumer, windows, correlation, agents, and RAG.
- Performance experiments testing varying event publishing rates (50, 500, 2000, 5000 eps) and window sizes (5s, 10s, 30s).
- Metric evaluation: Accuracy, Precision, Recall, F1-Score, Detection Latency, Consumer Lag.

### Stage 8: Deliverables & Documentation
- Comprehensive documentation:
  - `README.md`
  - `SPA_PERFORMANCE_REPORT.md`
  - `AGENTIC_AI_DOCUMENTATION.md`
  - `TESTING_REPORT.md`
  - Sample incident reports in `artifacts/sample_investigations/`.

---

## 4. Directory Structure to be Created

```
/Users/yashna/edaspa/
├── EDA/                         # Preserved Phase 1 EDA (Untouched)
├── csv/                         # Converted CSV dataset files (Untouched)
├── models/                      # Saved ML models & feature scalers
│   ├── threat_detector.joblib
│   └── scaler.joblib
├── knowledge_base/              # Local MITRE ATT&CK Knowledge Base
│   └── mitre_attack.json
├── src/
│   ├── __init__.py
│   ├── config.py                # Centralized configuration
│   ├── models/
│   │   ├── __init__.py
│   │   ├── train_detector.py    # Training script
│   │   └── feature_pipeline.py  # Feature transformation
│   ├── streaming/
│   │   ├── __init__.py
│   │   ├── bus.py               # Kafka / Embedded Streaming Bus
│   │   ├── producer.py          # Real-time event replayer
│   │   ├── consumer.py          # Event consumer
│   │   ├── window_processor.py  # Sliding/tumbling window engine
│   │   └── metrics.py           # Throughput, latency, lag metrics
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── rules.py             # Rule-based heuristics
│   │   ├── correlation.py       # Multi-event correlation
│   │   └── engine.py            # Hybrid detection engine
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── tools.py             # Agent tool definitions
│   │   ├── rag.py               # Local MITRE ATT&CK RAG
│   │   ├── threat_detection_agent.py
│   │   ├── investigation_agent.py
│   │   ├── threat_intel_agent.py
│   │   ├── security_response_agent.py
│   │   └── orchestrator.py      # LangGraph state machine
│   ├── api/
│   │   ├── __init__.py
│   │   └── server.py            # FastAPI + WebSockets backend
│   └── dashboard/
│       ├── index.html           # Modern SOC dashboard HTML
│       ├── styles.css           # Premium cyber SOC CSS
│       └── app.js               # Reactive frontend logic
├── tests/
│   ├── test_streaming.py
│   ├── test_detection.py
│   ├── test_agents.py
│   └── run_performance_benchmark.py
├── run_system.py                # Single-command launcher
├── requirements.txt
├── PROJECT_IMPLEMENTATION_PLAN.md
├── README.md
├── SPA_PERFORMANCE_REPORT.md
└── AGENTIC_AI_DOCUMENTATION.md
```

---

## 5. Execution Strategy & Next Steps

We will proceed strictly modularly, verifying each component thoroughly:
1. **Model & Preprocessing Training:** Train the threat detector using existing EDA feature findings.
2. **Streaming & Windowing Engine:** Implement the Kafka-compatible streaming bus, replayer, and stateful sliding window processor.
3. **Correlation & Detection:** Build the hybrid correlation engine detecting Brute Force, Port Scan, DoS, DDoS, Botnet, and Web Attacks.
4. **Agentic AI & RAG:** Construct the local MITRE ATT&CK repository and 4 LangGraph agents with tool execution and HITL gates.
5. **Real-Time SOC Dashboard:** Develop the full-stack FastAPI + WebSocket SOC user interface.
6. **Testing, Benchmarking & Documentation:** Execute validation tests, capture throughput/latency metrics, and generate reports.
