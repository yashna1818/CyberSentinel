# AGENTIC AI ARCHITECTURE & IMPLEMENTATION DOCUMENTATION
## Real-Time Cybersecurity Log Correlation & Intelligent Threat Investigation Platform

---

## 1. Multi-Agent System Overview

The multi-agent cybersecurity investigation subsystem is implemented using **LangGraph** (StateGraph), orchestrating four specialized agents that collaborate autonomously to triage, investigate, correlate, and respond to detected network intrusions.

```
┌────────────────────────────────────────────────────────────────────────┐
│              LANGGRAPH AUTONOMOUS MULTI-AGENT WORKFLOW                 │
│                                                                        │
│  [ Detected Threat Event from Streaming Engine (Kafka Topic) ]         │
│                                │                                       │
│                                ▼                                       │
│             ┌─────────────────────────────────────┐                    │
│             │   AGENT 1: THREAT DETECTION AGENT   │                    │
│             │   - Window Triage                   │                    │
│             │   - Severity Assessment             │                    │
│             │   - Evidence Compilation            │                    │
│             └──────────────────┬──────────────────┘                    │
│                                │ State Passing                         │
│                                ▼                                       │
│             ┌─────────────────────────────────────┐                    │
│             │  AGENT 2: ATTACK INVESTIGATION AGENT│                    │
│             │   - Timeline Reconstruction         │                    │
│             │   - Forensic IP History Query       │                    │
│             │   - Multi-Stage Campaign Assessment │                    │
│             └──────────────────┬──────────────────┘                    │
│                                │ State Passing                         │
│                                ▼                                       │
│             ┌─────────────────────────────────────┐                    │
│             │ AGENT 3: THREAT INTELLIGENCE AGENT  │                    │
│             │   - Local MITRE ATT&CK RAG          │                    │
│             │   - Technique Mapping (e.g. T1110)  │                    │
│             │   - Adversary Objective Attribution │                    │
│             └──────────────────┬──────────────────┘                    │
│                                │ State Passing                         │
│                                ▼                                       │
│             ┌─────────────────────────────────────┐                    │
│             │  AGENT 4: SECURITY RESPONSE AGENT   │                    │
│             │   - Prioritized Defenses            │                    │
│             │   - Human-in-the-Loop (HITL) Gate   │                    │
│             │   - Action Justifications           │                    │
│             └──────────────────┬──────────────────┘                    │
│                                │ State Passing                         │
│                                ▼                                       │
│             ┌─────────────────────────────────────┐                    │
│             │         CONSOLIDATION NODE          │                    │
│             │   - Standardized Forensic Report    │                    │
│             │   - Workflow Audit Trail            │                    │
│             │   - Broadcast to SOC Dashboard      │                    │
│             └─────────────────────────────────────┘                    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Nine Agentic AI Concepts Implemented in Working Code

### 1. Multi-Agent Architecture
- Four distinct, loosely coupled agents with dedicated functional specializations (`threat_detection_agent`, `attack_investigation_agent`, `threat_intel_agent`, `security_response_agent`).
- Orchestrated via `langgraph.graph.StateGraph` in `src/agents/orchestrator.py`.

### 2. Autonomous Task Planning & Execution
- Upon receiving a threat trigger from the Kafka `detected-threats` stream, the orchestrator autonomously initiates an investigation workflow, determines which tools to call, and progresses from triage through mitigation formulation.

### 3. Tool Calling and Function Execution
- Implemented in `src/agents/tools.py` via `InvestigationToolRegistry`:
  - `fetch_related_events(src_ip, dst_ip, limit)`: Forensic extraction of raw flows.
  - `get_ip_reputation_history(ip_address)`: Historical threat profile and cumulative risk score.
  - `inspect_event_window(threat_id)`: Aggregate sliding-window metrics.
  - `get_detection_evidence(threat_id)`: Statistical evidence verification.
  - `query_mitre_attack(category, query)`: Semantic retrieval from MITRE database.
  - `create_human_approval_request(...)`: Generation of pending mitigation sign-offs.

### 4. Retrieval-Augmented Generation (RAG)
- Uses an authentic local MITRE ATT&CK Enterprise Matrix repository (`knowledge_base/mitre_attack.json`) covering standard techniques:
  - `T1110.001`: Brute Force Password Guessing (FTP/SSH Patator)
  - `T1046`: Network Service Discovery (Port Scan)
  - `T1498.001`: Network Denial of Service: Direct Flood (DDoS, DoS Hulk)
  - `T1499.003`: Endpoint Denial of Service: Application Exhaustion (Slowloris, Slowhttptest)
  - `T1190`: Exploit Public-Facing Application (Web SQLi, XSS)
  - `T1071.001`: Web Protocols C2 (Botnet)
  - `T1210`: Exploitation of Remote Services (Lateral Infiltration)
- Zero hallucination: all IDs and references are verified against the local knowledge base.

### 5. Short-Term Investigation Memory
- Maintained inside `IncidentInvestigationState` and `InvestigationToolRegistry`:
  - Active incident context passed through graph execution.
  - IP reputation dossiers tracking recurring offender profiles and alert counts.
  - Ephemeral raw flow buffer enabling backward-looking correlation.

### 6. Inter-Agent Communication
- Standardized typed dictionary (`IncidentInvestigationState`) passed along directed edges of the LangGraph graph:
  - `detection_findings` $\rightarrow$ `investigation_findings` $\rightarrow$ `threat_intel_findings` $\rightarrow$ `response_recommendations` $\rightarrow$ `consolidated_report`.

### 7. Context-Aware Reasoning
- Reconstructs network activity chronologically:
  - Evaluates whether an incident is an isolated anomaly or part of a multi-stage kill chain (e.g., initial port scan followed by authentication brute force and lateral movement).

### 8. Human-in-the-Loop (HITL) Safeguards
- Prohibits automated execution of disruptive or high-risk defensive actions (such as dropping customer IP ranges, blackholing subnets, or isolating critical internal servers).
- Enforces an approval queue in `src/agents/tools.py` and provides interactive SOC analyst sign-off controls via the web dashboard.

### 9. Guardrails and Structured Outputs
- Enforces structured JSON contracts between agents.
- Fallback mechanics ensure that if external language model APIs are unreachable or rate-limited, the multi-agent reasoning chain completes deterministically using rule-assisted forensic correlation.

---

## 3. Sample Incident Investigation Output

Below is an authentic investigation report generated by the multi-agent system:

```json
{
  "incident_id": "INC-THREAT-F28B490A",
  "timestamp": "2026-11-01T23:38:00.125Z",
  "threat_summary": {
    "threat_id": "THREAT-F28B490A",
    "attack_category": "Brute Force",
    "severity": "HIGH",
    "confidence_score": 0.94,
    "source_ip": "205.174.165.73",
    "destination_ip": "192.168.10.51",
    "evidence": [
      "12 repeated authentication sessions targeting SSH (22)",
      "Short connection lifetimes with minimal transferred payload bytes"
    ]
  },
  "investigation_summary": "Forensic Investigation for 205.174.165.73: Reconstructed 8 correlated network flows. Target host 192.168.10.51 received repeated probes. Host Reputation status: KNOWN_OFFENDER (Historical Risk Score: 60.0/100). Coordinated Campaign Assessment: CONFIRMED MULTI-STAGE CAMPAIGN.",
  "mitre_attack": {
    "technique_id": "T1110",
    "technique_name": "Brute Force: Password Guessing",
    "tactic": "Credential Access",
    "adversary_objective": "Obtain valid user credentials to penetrate perimeter access and establish remote shell access."
  },
  "recommended_mitigations": [
    {
      "action": "Enforce Account Lockout on Target Daemon (192.168.10.51)",
      "type": "CONTAINMENT",
      "risk": "LOW",
      "automated_safe": true,
      "rationale": "Stop automated password spraying attempts."
    },
    {
      "action": "Blacklist Source IP 205.174.165.73 on Perimeter Bastion",
      "type": "DISRUPTIVE_REMEDIATION",
      "risk": "HIGH",
      "automated_safe": false,
      "rationale": "Repeated credential attacks from 205.174.165.73 warrant containment."
    }
  ],
  "human_approval_required": true,
  "pending_approvals": [
    {
      "approval_id": "APPR-8B490A",
      "action_name": "Blacklist Source IP 205.174.165.73 on Perimeter Bastion",
      "target_entity": "205.174.165.73",
      "risk_level": "HIGH",
      "status": "PENDING_APPROVAL"
    }
  ],
  "status": "AWAITING_ANALYST_APPROVAL"
}
```
