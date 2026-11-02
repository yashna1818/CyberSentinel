import time
from typing import Dict, Any, List, Optional
from src.agents.rag import mitre_rag

class InvestigationToolRegistry:
    """
    Central tool execution registry for the multi-agent investigation system.
    Provides callable tools with structured inputs and JSON-serializable outputs.
    """
    def __init__(self):
        # Ephemeral event store for tool access
        self.recent_events: List[Dict[str, Any]] = []
        self.threat_registry: Dict[str, Dict[str, Any]] = {}
        self.ip_dossiers: Dict[str, Dict[str, Any]] = {}
        self.human_approval_queue: Dict[str, Dict[str, Any]] = {}

    def register_event(self, event: Dict[str, Any]):
        self.recent_events.append(event)
        if len(self.recent_events) > 5000:
            self.recent_events.pop(0)

    def register_threat(self, threat: Dict[str, Any]):
        t_id = threat.get("threat_id")
        if t_id:
            self.threat_registry[t_id] = threat
            
            src_ip = threat.get("src_ip")
            if src_ip:
                if src_ip not in self.ip_dossiers:
                    self.ip_dossiers[src_ip] = {
                        "ip": src_ip,
                        "first_seen": threat.get("timestamp"),
                        "last_seen": threat.get("timestamp"),
                        "incidents": [],
                        "total_alerts": 0,
                        "risk_score": 0.0
                    }
                dossier = self.ip_dossiers[src_ip]
                dossier["last_seen"] = threat.get("timestamp")
                dossier["total_alerts"] += 1
                dossier["incidents"].append({
                    "threat_id": t_id,
                    "category": threat.get("attack_category"),
                    "severity": threat.get("severity")
                })
                # Bump risk score
                sev_weights = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
                dossier["risk_score"] = min(100.0, dossier["risk_score"] + sev_weights.get(threat.get("severity"), 5))

    # =========================================================================
    # TOOL 1: Fetch Related Events
    # =========================================================================
    def fetch_related_events(self, src_ip: str, dst_ip: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieves raw flow records associated with an IP address to reconstruct activity."""
        results = []
        for ev in reversed(self.recent_events):
            if ev.get("src_ip") == src_ip:
                if dst_ip is None or ev.get("dst_ip") == dst_ip:
                    results.append({
                        "event_id": ev.get("event_id"),
                        "timestamp": ev.get("timestamp"),
                        "src_ip": ev.get("src_ip"),
                        "dst_ip": ev.get("dst_ip"),
                        "dst_port": ev.get("dst_port"),
                        "protocol": ev.get("protocol"),
                        "flow_duration": ev.get("Flow Duration"),
                        "packets": ev.get("Total Fwd Packets"),
                        "syn_flag": ev.get("SYN Flag Count")
                    })
                    if len(results) >= limit:
                        break
        return results

    # =========================================================================
    # TOOL 2: Retrieve IP Activity History & Reputation
    # =========================================================================
    def get_ip_reputation_history(self, ip_address: str) -> Dict[str, Any]:
        """Queries historical incidents, risk score, and behavioral classification for an IP."""
        dossier = self.ip_dossiers.get(ip_address)
        if not dossier:
            return {
                "ip": ip_address,
                "status": "NO_PREVIOUS_HISTORY",
                "risk_score": 0.0,
                "total_alerts": 0,
                "incident_count": 0
            }
        return {
            "ip": ip_address,
            "status": "KNOWN_OFFENDER" if dossier["risk_score"] > 50 else "SUSPICIOUS",
            "risk_score": dossier["risk_score"],
            "total_alerts": dossier["total_alerts"],
            "first_seen": dossier["first_seen"],
            "last_seen": dossier["last_seen"],
            "recent_incidents": dossier["incidents"][-5:]
        }

    # =========================================================================
    # TOOL 3: Inspect Correlated Event Window
    # =========================================================================
    def inspect_event_window(self, threat_id: str) -> Dict[str, Any]:
        """Inspects statistical metrics, sliding window aggregates, and packet rates for an alert."""
        threat = self.threat_registry.get(threat_id)
        if not threat:
            return {"error": f"Threat {threat_id} not found in active registry"}
        return {
            "threat_id": threat_id,
            "attack_category": threat.get("attack_category"),
            "num_related_events": threat.get("num_related_events"),
            "window_metrics": threat.get("window_metrics", {}),
            "severity": threat.get("severity"),
            "confidence_score": threat.get("confidence_score")
        }

    # =========================================================================
    # TOOL 4: Retrieve Detection Evidence
    # =========================================================================
    def get_detection_evidence(self, threat_id: str) -> List[str]:
        """Retrieves forensic supporting evidence strings compiled during stream correlation."""
        threat = self.threat_registry.get(threat_id)
        if not threat:
            return []
        return threat.get("supporting_evidence", [])

    # =========================================================================
    # TOOL 5: Query Local MITRE ATT&CK RAG
    # =========================================================================
    def query_mitre_attack(self, attack_category: str, context_query: str = "") -> List[Dict[str, Any]]:
        """Executes RAG retrieval against authentic local MITRE ATT&CK database."""
        return mitre_rag.query(attack_category=attack_category, query_text=context_query, top_k=2)

    # =========================================================================
    # TOOL 6: Request Human-in-the-Loop Approval for Remediation
    # =========================================================================
    def create_human_approval_request(
        self,
        incident_id: str,
        action_name: str,
        target_entity: str,
        rationale: str,
        risk_level: str
    ) -> Dict[str, Any]:
        """
        Enforces human-in-the-loop safety guardrails.
        Creates a pending mitigation action requiring explicit SOC analyst sign-off.
        """
        req_id = f"APPR-{incident_id[-6:]}"
        approval_item = {
            "approval_id": req_id,
            "incident_id": incident_id,
            "action_name": action_name,
            "target_entity": target_entity,
            "rationale": rationale,
            "risk_level": risk_level,
            "status": "PENDING_APPROVAL",
            "created_at": time.time(),
            "analyst_notes": None
        }
        self.human_approval_queue[req_id] = approval_item
        return approval_item

# Global tool registry
tool_registry = InvestigationToolRegistry()
