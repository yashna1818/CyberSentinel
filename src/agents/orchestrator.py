import os
import json
import time
import uuid
import logging
from typing import Dict, Any, List, Optional, TypedDict
from datetime import datetime, timezone

from langgraph.graph import StateGraph, END
from src.agents.tools import tool_registry
from src.agents.rag import mitre_rag
from src.streaming.metrics import stream_metrics

logger = logging.getLogger("MultiAgentOrchestrator")

# TypedDict State for LangGraph Orchestration
class IncidentInvestigationState(TypedDict):
    incident_id: str
    threat_alert: Dict[str, Any]
    current_agent: str
    workflow_steps: List[Dict[str, Any]]
    detection_findings: Dict[str, Any]
    investigation_findings: Dict[str, Any]
    threat_intel_findings: Dict[str, Any]
    response_recommendations: Dict[str, Any]
    consolidated_report: Dict[str, Any]
    status: str
    error: Optional[str]

# =============================================================================
# AGENT 1: THREAT DETECTION AGENT
# =============================================================================
def threat_detection_agent_node(state: IncidentInvestigationState) -> Dict[str, Any]:
    t0 = time.time()
    threat = state["threat_alert"]
    threat_id = threat.get("threat_id")
    src_ip = threat.get("src_ip")
    cat = threat.get("attack_category")
    
    # Tool Execution: Inspect event window & get evidence
    window_data = tool_registry.inspect_event_window(threat_id)
    evidence = tool_registry.get_detection_evidence(threat_id)
    
    # Assess severity & triage
    severity = threat.get("severity", "MEDIUM")
    confidence = threat.get("confidence_score", 0.85)
    
    reasoning = (
        f"Triage Evaluation: Detected {cat} activity originating from {src_ip}. "
        f"Window metrics indicate {window_data.get('num_related_events', 1)} correlated flows. "
        f"Assigned triage level {severity} with statistical confidence {confidence*100:.1f}%. "
        f"Evidence indicates threshold breach: {'; '.join(evidence[:2])}."
    )
    
    findings = {
        "agent": "Threat Detection Agent",
        "triage_decision": "ESCALATE_FOR_FORENSIC_INVESTIGATION",
        "threat_id": threat_id,
        "assessed_severity": severity,
        "confidence_score": confidence,
        "primary_attack_vector": cat,
        "tool_calls": [
            {"tool": "inspect_event_window", "args": {"threat_id": threat_id}, "result_summary": f"{window_data.get('num_related_events')} events"},
            {"tool": "get_detection_evidence", "args": {"threat_id": threat_id}, "result_summary": f"{len(evidence)} evidence points"}
        ],
        "reasoning": reasoning
    }
    
    step_log = {
        "step_index": 1,
        "agent": "Threat Detection Agent",
        "action": "Triage & Evidence Extraction",
        "details": reasoning,
        "timestamp": time.time()
    }
    
    return {
        "current_agent": "Attack Investigation Agent",
        "detection_findings": findings,
        "workflow_steps": state.get("workflow_steps", []) + [step_log]
    }

# =============================================================================
# AGENT 2: ATTACK INVESTIGATION AGENT
# =============================================================================
def attack_investigation_agent_node(state: IncidentInvestigationState) -> Dict[str, Any]:
    threat = state["threat_alert"]
    src_ip = threat.get("src_ip")
    dst_ip = threat.get("dst_ip")
    cat = threat.get("attack_category")
    
    # Tool Execution: Reconstruct activity & query IP reputation
    related_events = tool_registry.fetch_related_events(src_ip, dst_ip, limit=8)
    reputation = tool_registry.get_ip_reputation_history(src_ip)
    
    is_coordinated = (
        reputation.get("incident_count", 0) > 1 or 
        len(related_events) >= 5 or 
        "Port Scan" in [inc.get("category") for inc in reputation.get("recent_incidents", [])]
    )
    
    timeline = []
    for ev in related_events[:5]:
        timeline.append(f"[{ev.get('timestamp')}] Protocol {ev.get('protocol')} to port {ev.get('dst_port')} (Packets: {ev.get('packets')})")

    explanation = (
        f"Forensic Investigation for {src_ip}: Reconstructed {len(related_events)} correlated network flows. "
        f"Target host {dst_ip} received repeated probes. "
        f"Host Reputation status: {reputation.get('status')} (Historical Risk Score: {reputation.get('risk_score')}/100). "
        f"Coordinated Campaign Assessment: {'CONFIRMED MULTI-STAGE CAMPAIGN' if is_coordinated else 'ISOLATED HIGH-VOLUME INCIDENT'}."
    )
    
    findings = {
        "agent": "Attack Investigation Agent",
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "ip_risk_score": reputation.get("risk_score"),
        "is_coordinated_campaign": is_coordinated,
        "reconstructed_timeline": timeline,
        "total_flows_inspected": len(related_events),
        "tool_calls": [
            {"tool": "fetch_related_events", "args": {"src_ip": src_ip, "limit": 8}, "result_summary": f"Retrieved {len(related_events)} flows"},
            {"tool": "get_ip_reputation_history", "args": {"ip_address": src_ip}, "result_summary": f"Risk Score {reputation.get('risk_score')}"}
        ],
        "explanation": explanation
    }
    
    step_log = {
        "step_index": 2,
        "agent": "Attack Investigation Agent",
        "action": "Timeline Reconstruction & Threat Attribution",
        "details": explanation,
        "timestamp": time.time()
    }
    
    return {
        "current_agent": "Threat Intelligence Agent",
        "investigation_findings": findings,
        "workflow_steps": state.get("workflow_steps", []) + [step_log]
    }

# =============================================================================
# AGENT 3: THREAT INTELLIGENCE AGENT (RAG with Local MITRE ATT&CK)
# =============================================================================
def threat_intel_agent_node(state: IncidentInvestigationState) -> Dict[str, Any]:
    threat = state["threat_alert"]
    cat = threat.get("attack_category", "Benign")
    detection_findings = state.get("detection_findings", {})
    
    # Tool Execution: Local MITRE ATT&CK RAG Query
    rag_results = tool_registry.query_mitre_attack(
        attack_category=cat,
        context_query=f"{threat.get('src_ip')} {threat.get('dst_ip')} {cat}"
    )
    
    mapped_techniques = []
    for item in rag_results:
        mapped_techniques.append({
            "technique_id": item.get("technique_id"),
            "sub_technique_id": item.get("sub_technique_id"),
            "technique_name": item.get("name"),
            "tactic": item.get("tactic"),
            "tactic_id": item.get("tactic_id"),
            "description": item.get("description"),
            "adversary_objective": item.get("objectives"),
            "mitigations": item.get("mitigations", []),
            "detection_guidance": item.get("detection"),
            "references": item.get("references", []),
            "relevance_score": item.get("relevance_score")
        })

    primary_tech = mapped_techniques[0] if mapped_techniques else {}
    summary = (
        f"Threat Intel RAG Mapping: Identified MITRE ATT&CK Technique {primary_tech.get('technique_id')} "
        f"('{primary_tech.get('technique_name')}') under Tactic {primary_tech.get('tactic')} ({primary_tech.get('tactic_id')}). "
        f"Adversary Objective: {primary_tech.get('adversary_objective')}."
    )
    
    findings = {
        "agent": "Threat Intelligence Agent",
        "knowledge_source": "Local MITRE ATT&CK Enterprise Matrix v14.1",
        "mapped_techniques": mapped_techniques,
        "primary_technique_id": primary_tech.get("technique_id"),
        "primary_tactic": primary_tech.get("tactic"),
        "adversary_objective": primary_tech.get("adversary_objective"),
        "tool_calls": [
            {"tool": "query_mitre_attack", "args": {"attack_category": cat}, "result_summary": f"Matched {len(mapped_techniques)} authentic MITRE techniques"}
        ],
        "summary": summary
    }
    
    step_log = {
        "step_index": 3,
        "agent": "Threat Intelligence Agent",
        "action": "MITRE ATT&CK RAG Mapping",
        "details": summary,
        "timestamp": time.time()
    }
    
    return {
        "current_agent": "Security Response Agent",
        "threat_intel_findings": findings,
        "workflow_steps": state.get("workflow_steps", []) + [step_log]
    }

# =============================================================================
# AGENT 4: SECURITY RESPONSE AGENT (Human-in-the-Loop Safeguards)
# =============================================================================
def security_response_agent_node(state: IncidentInvestigationState) -> Dict[str, Any]:
    incident_id = state["incident_id"]
    threat = state["threat_alert"]
    src_ip = threat.get("src_ip")
    dst_ip = threat.get("dst_ip")
    cat = threat.get("attack_category")
    severity = threat.get("severity", "MEDIUM")
    intel = state.get("threat_intel_findings", {})
    mapped_techniques = intel.get("mapped_techniques", [])
    
    # Formulate defensible recommendations based on MITRE mitigations
    recommended_actions = []
    
    if cat in ["DDoS", "DoS"]:
        recommended_actions.append({
            "action": "Enable Rate-Limiting & Upstream Filtering",
            "type": "IMMEDIATE_CONTAINMENT",
            "risk": "LOW",
            "automated_safe": True,
            "rationale": f"Throttle ingress SYN and packet flood targeting {dst_ip}."
        })
        recommended_actions.append({
            "action": f"Block Attacker IP {src_ip} at Edge Firewall",
            "type": "DISRUPTIVE_REMEDIATION",
            "risk": "HIGH",
            "automated_safe": False, # Requires HITL approval
            "rationale": f"High-confidence flood source {src_ip} requires network isolation."
        })
    elif cat == "Brute Force":
        recommended_actions.append({
            "action": f"Enforce Account Lockout on Target Daemon ({dst_ip})",
            "type": "CONTAINMENT",
            "risk": "LOW",
            "automated_safe": True,
            "rationale": "Stop automated password spraying attempts."
        })
        recommended_actions.append({
            "action": f"Blacklist Source IP {src_ip} on Perimeter Bastion",
            "type": "DISRUPTIVE_REMEDIATION",
            "risk": "HIGH",
            "automated_safe": False, # Requires HITL approval
            "rationale": f"Repeated credential attacks from {src_ip} warrant containment."
        })
    elif cat == "Port Scan":
        recommended_actions.append({
            "action": f"Add {src_ip} to Dynamic Watchlist & Enable Verbose NetFlow Logging",
            "type": "MONITORING",
            "risk": "NONE",
            "automated_safe": True,
            "rationale": "Monitor for subsequent exploitation or brute force escalation."
        })
    elif cat == "Infiltration":
        recommended_actions.append({
            "action": f"Isolate Compromised Internal Workstation {src_ip}",
            "type": "HOST_CONTAINMENT",
            "risk": "CRITICAL",
            "automated_safe": False, # Requires HITL approval
            "rationale": "Prevent lateral movement and credential dumping across internal subnet."
        })
    else:
        recommended_actions.append({
            "action": f"Review WAF Logs & Patch Application Vulnerability on {dst_ip}",
            "type": "INVESTIGATION",
            "risk": "LOW",
            "automated_safe": True,
            "rationale": "Verify whether exploit payload achieved code execution."
        })

    # Enforce Human-in-the-Loop Gate for any High or Critical Disruptive Action
    approval_requests = []
    for act in recommended_actions:
        if not act["automated_safe"]:
            appr = tool_registry.create_human_approval_request(
                incident_id=incident_id,
                action_name=act["action"],
                target_entity=src_ip,
                rationale=act["rationale"],
                risk_level=act["risk"]
            )
            approval_requests.append(appr)

    response_plan = {
        "agent": "Security Response Agent",
        "incident_priority": f"P1-{severity}" if severity in ["CRITICAL", "HIGH"] else "P2-ELEVATED",
        "recommended_actions": recommended_actions,
        "pending_human_approvals": approval_requests,
        "hitl_enforced": len(approval_requests) > 0,
        "tool_calls": [
            {"tool": "create_human_approval_request", "args": {"incident_id": incident_id}, "result_summary": f"Generated {len(approval_requests)} pending approvals"}
        ],
        "summary": (
            f"Response Plan formulated: Prioritized as {severity} incident. "
            f"Generated {len(recommended_actions)} actionable countermeasures. "
            f"Human-in-the-Loop Guardrail: {len(approval_requests)} potentially disruptive action(s) paused for analyst approval."
        )
    }

    step_log = {
        "step_index": 4,
        "agent": "Security Response Agent",
        "action": "Defensive Mitigation & HITL Verification",
        "details": response_plan["summary"],
        "timestamp": time.time()
    }

    return {
        "current_agent": "Consolidation Node",
        "response_recommendations": response_plan,
        "workflow_steps": state.get("workflow_steps", []) + [step_log]
    }

# =============================================================================
# CONSOLIDATION & FINAL REPORTING NODE
# =============================================================================
def consolidate_report_node(state: IncidentInvestigationState) -> Dict[str, Any]:
    threat = state["threat_alert"]
    det = state.get("detection_findings", {})
    inv = state.get("investigation_findings", {})
    intel = state.get("threat_intel_findings", {})
    resp = state.get("response_recommendations", {})
    
    report = {
        "incident_id": state["incident_id"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat_summary": {
            "threat_id": threat.get("threat_id"),
            "attack_category": threat.get("attack_category"),
            "severity": threat.get("severity"),
            "confidence_score": threat.get("confidence_score"),
            "source_ip": threat.get("src_ip"),
            "destination_ip": threat.get("dst_ip"),
            "evidence": threat.get("supporting_evidence", [])
        },
        "investigation_summary": inv.get("explanation"),
        "mitre_attack": {
            "technique_id": intel.get("primary_technique_id"),
            "technique_name": intel.get("mapped_techniques", [{}])[0].get("technique_name") if intel.get("mapped_techniques") else "Unknown",
            "tactic": intel.get("primary_tactic"),
            "adversary_objective": intel.get("adversary_objective")
        },
        "recommended_mitigations": resp.get("recommended_actions", []),
        "human_approval_required": resp.get("hitl_enforced", False),
        "pending_approvals": resp.get("pending_human_approvals", []),
        "workflow_audit_trail": state.get("workflow_steps", []),
        "status": "AWAITING_ANALYST_APPROVAL" if resp.get("hitl_enforced") else "RESOLVED"
    }
    
    return {
        "current_agent": "COMPLETED",
        "consolidated_report": report,
        "status": report["status"]
    }

# =============================================================================
# BUILD LANGGRAPH WORKFLOW
# =============================================================================
def build_multi_agent_workflow() -> Any:
    workflow = StateGraph(IncidentInvestigationState)
    
    # Add Agent Nodes
    workflow.add_node("threat_detection_agent", threat_detection_agent_node)
    workflow.add_node("attack_investigation_agent", attack_investigation_agent_node)
    workflow.add_node("threat_intel_agent", threat_intel_agent_node)
    workflow.add_node("security_response_agent", security_response_agent_node)
    workflow.add_node("consolidate_report", consolidate_report_node)
    
    # Define Directed Edges
    workflow.set_entry_point("threat_detection_agent")
    workflow.add_edge("threat_detection_agent", "attack_investigation_agent")
    workflow.add_edge("attack_investigation_agent", "threat_intel_agent")
    workflow.add_edge("threat_intel_agent", "security_response_agent")
    workflow.add_edge("security_response_agent", "consolidate_report")
    workflow.add_edge("consolidate_report", END)
    
    return workflow.compile()

class MultiAgentOrchestrator:
    """
    Central orchestration controller executing the multi-agent cybersecurity investigation.
    Maintains investigation context, short-term memory, and error recovery.
    """
    def __init__(self):
        self.app = build_multi_agent_workflow()
        self.incident_history: List[Dict[str, Any]] = []

    def investigate(self, threat_alert: Dict[str, Any]) -> Dict[str, Any]:
        t_start = time.time()
        incident_id = f"INC-{threat_alert.get('threat_id', uuid.uuid4().hex[:8])}"
        
        initial_state: IncidentInvestigationState = {
            "incident_id": incident_id,
            "threat_alert": threat_alert,
            "current_agent": "threat_detection_agent",
            "workflow_steps": [],
            "detection_findings": {},
            "investigation_findings": {},
            "threat_intel_findings": {},
            "response_recommendations": {},
            "consolidated_report": {},
            "status": "INVESTIGATING",
            "error": None
        }
        
        try:
            final_state = self.app.invoke(initial_state)
            report = final_state.get("consolidated_report", {})
            self.incident_history.append(report)
            
            # Record agent investigation latency
            proc_lat = (time.time() - t_start) * 1000.0
            stream_metrics.update_agent_latency(proc_lat)
            stream_metrics.record_alert()
            
            return report
        except Exception as e:
            logger.error(f"Error executing multi-agent investigation: {e}")
            stream_metrics.record_error()
            return {
                "incident_id": incident_id,
                "error": str(e),
                "status": "INVESTIGATION_FAILED"
            }

# Global orchestrator singleton
agent_orchestrator = MultiAgentOrchestrator()
