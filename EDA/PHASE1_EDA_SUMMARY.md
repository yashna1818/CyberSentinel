# PHASE-I PRESENTATION SUMMARY: EXPLORATORY DATA ANALYSIS
## Project: Real-Time Cyber Security Log Correlation Using Apache Kafka

---

## SLIDE 1 — DATASET DESCRIPTION

- **Dataset Used:** CIC-IDS2017 Comprehensive Network-Flow Cybersecurity Dataset
- **Number of Files:** 8 Parquet files (Daily attack captures: Monday through Friday)
- **Total Records:** `2,313,810` network flow events
- **Number of Features:** 78 original flow features (80 total including derived `category` and `traffic_type`)
- **Data Format:** Apache Parquet format (Total uncompressed size: ~1.42 GB, on-disk compressed size: `258.12 MB`)
- **Traffic Categories (8 Capture Profiles):**
  1. **DoS (Denial of Service):** 584,991 flows (25.28%)
  2. **Benign (Normal Baseline):** 458,831 flows (19.83%)
  3. **Brute Force (FTP/SSH Patator):** 389,714 flows (16.84%)
  4. **DDoS (Distributed DoS):** 221,264 flows (9.56%)
  5. **Infiltration (Lateral Movement):** 207,630 flows (8.97%)
  6. **Botnet (ARES Botnet):** 176,038 flows (7.61%)
  7. **Web Attacks (XSS, SQLi, Brute Force):** 155,820 flows (6.73%)
  8. **Port Scan (Reconnaissance Probes):** 119,522 flows (5.17%)

---

## SLIDE 2 — EDA RESULTS

### Key Numerical Findings:
1. **Total Volume Analyzed:** `2,313,810` flows processed with 100% schema consistency across all 8 files.
2. **Benign vs. Attack Composition:**
   - **Attack Capture Traffic:** `1,854,979` events (**80.17%**)
   - **Pure Benign Baseline Capture:** `458,831` events (**19.83%**)
   - *Granular ground-truth breakdown:* `1,977,318` flows (85.46%) normal traffic vs `336,492` flows (14.54%) active malicious attack instances.
3. **Dominant Attack Category:** **DoS (Denial of Service)** is the largest attack category with `584,991` records (25.28%), followed by **Brute Force** (`389,714` records, 16.84%) and **DDoS** (`221,264` records, 9.56%).
4. **Data Hygiene & Missing Values:** **0 missing values (0.00%)** detected across all 80 features and 2.31M rows.
5. **Duplicate Record Volume:** Exactly **`82,004` duplicate flows (3.54%)** identified and intentionally preserved (natural artifact of high-frequency TCP scanning and recurring network heartbeats).
6. **Transport Protocol Distribution:**
   - **TCP (Protocol 6):** 1,363,379 flows (**58.92%**) — Dominates DDoS (85.94% TCP) and DoS (67.41% TCP).
   - **UDP (Protocol 17):** 948,842 flows (**41.01%**)
   - **HOPOPT / ICMP (Protocol 0):** 1,589 flows (**0.07%**)

### Important Feature & Correlation Observations:
- **Severe Metric Skewness:** Features like `Flow Duration` (median: 64.78 ms, max: 120 s) and `Flow Bytes/s` exhibit multi-order heavy-tail distributions requiring log-transformation or sliding percentile thresholds.
- **Deterministic Redundancies:** Subflow metrics (e.g., `Total Fwd Packets` and `Subflow Fwd Packets`) correlate at $r = 1.0000$, enabling schema pruning for high-throughput stream transmission.
- **Temporal Status:** Absolute date/timestamp columns were stripped in the `no-metadata` Parquet files; however, relative temporal metrics (`Flow Duration`, `Flow IAT Mean`, `Active/Idle times`) provide microsecond-level timing dynamics for event replay.

---

## SLIDE 3 — RELEVANCE TO PROJECT

### Real-Time Kafka Pipeline Architecture:

```
[ Historical Parquet Dataset (2.31M Records) ]
                    │
                    ▼
[ Python Streaming Event Replayer / JSON Producer ]
                    │
                    ▼  (Emits JSON events with dynamic UTC timestamps)
[ Apache Kafka Topic: 'security-logs' ]
                    │
                    ▼  (Sub-second sliding window aggregation & rule correlation)
[ Real-Time Stream Processing Engine (Flink / Spark / Faust) ]
                    │
                    ▼  (Filtered security alerts & threshold breaches)
[ Apache Kafka Topic: 'security-alerts' ]
                    │
                    ▼
[ Real-Time SecOps Dashboard / SIEM Alerting ]
```

### How EDA Directly Enables the Pipeline:
1. **Event Replay Mechanism:** The 2.31M historical flow records will be converted into structured JSON payloads and pushed to the Kafka `security-logs` topic. Inter-event delays will be paced using the calculated `Flow IAT Mean` to simulate realistic high-throughput enterprise network traffic.
2. **Sliding-Window Stateful Correlation:** Key discriminative features identified in EDA (`Flow Packets/s`, `SYN Flag Count`, `Flow Duration`, `Bwd Packets Length Total`) will serve as trigger metrics in real-time stream aggregation windows (e.g., 5-second tumbling windows detecting sudden packet-rate spikes indicative of DDoS/DoS).
3. **Multi-Stage Attack Correlation:** Low-volume attacks (e.g., Infiltration with 36 events, Web SQLi with 21 events) will be correlated across sequential stages (Port Scan $\rightarrow$ Brute Force $\rightarrow$ Infiltration) using stateful stream sessionization.
4. **Optimized Stream Payload:** Highly correlated feature pairs identified in EDA ($r = 1.0000$) can be safely pruned to minimize Kafka broker network serialization overhead and maximize event throughput.
