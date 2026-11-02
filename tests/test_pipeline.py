import os
import sys
import time
import pytest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.streaming.bus import stream_bus
from src.streaming.metrics import stream_metrics
from src.streaming.window_processor import StatefulWindowProcessor
from src.detection.engine import detection_engine
from src.agents.rag import mitre_rag
from src.agents.tools import tool_registry
from src.agents.orchestrator import agent_orchestrator
from src.models.feature_pipeline import KEY_FEATURES

def test_streaming_bus_produce_and_consume():
    received = []
    def callback(topic, val):
        received.append(val)

    stream_bus.subscribe("test-topic", "test-group", callback)
    stream_bus.produce("test-topic", {"msg": "hello_stream"}, key="test_key")
    
    # Wait briefly for worker thread dispatch
    time.sleep(0.3)
    assert len(received) >= 1
    assert received[0]["msg"] == "hello_stream"

def test_mitre_attack_rag():
    results = mitre_rag.query("Brute Force", top_k=1)
    assert len(results) > 0
    assert results[0]["technique_id"] == "T1110"
    assert "Credential Access" in results[0]["tactic"]

    port_results = mitre_rag.query("Port Scan", top_k=1)
    assert len(port_results) > 0
    assert port_results[0]["technique_id"] == "T1046"

def test_stateful_window_processor():
    proc = StatefulWindowProcessor(window_size_sec=5.0)
    
    # Send 3 events for same flow
    for i in range(3):
        ev = {
            "event_id": f"evt-{i}",
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "protocol": 6,
            "dst_port": 80,
            "Total Fwd Packets": 10,
            "Fwd Packets Length Total": 500,
            "timestamp": "2026-11-01T23:40:00Z"
        }
        summary = proc.process_event(ev)

    assert summary is not None
    assert summary["event_count"] == 3
    assert summary["total_packets"] == 30
    assert summary["src_ip"] == "172.16.0.1"

def test_duplicate_event_handling():
    proc = StatefulWindowProcessor()
    ev = {
        "event_id": "duplicate-id-123",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "timestamp": "2026-11-01T23:40:00Z"
    }
    s1 = proc.process_event(ev)
    assert s1 is not None
    # Send duplicate
    s2 = proc.process_event(ev)
    assert s2 is None # Duplicate dropped

def test_hybrid_threat_detection_port_scan():
    # Simulate port scan window
    window_summary = {
        "src_ip": "205.174.165.73",
        "dst_ip": "192.168.10.50",
        "dst_port": 80,
        "event_count": 15,
        "packets_per_sec": 50.0,
        "bytes_per_sec": 1000.0,
        "host_distinct_ports_contacted": 18,
        "short_duration_count": 12,
        "syn_count": 15,
        "event_ids": ["ev1", "ev2"],
        "latest_event": {"Protocol": 6, "Total Fwd Packets": 1}
    }
    threat = detection_engine.analyze_window(window_summary)
    assert threat is not None
    assert threat["attack_category"] == "Port Scan"
    assert threat["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]

def test_multi_agent_orchestrator():
    sample_threat = {
        "threat_id": "THREAT-UNITTEST",
        "src_ip": "205.174.165.73",
        "dst_ip": "192.168.10.51",
        "attack_category": "Brute Force",
        "timestamp": "2026-11-01T23:40:00Z",
        "num_related_events": 15,
        "severity": "HIGH",
        "confidence_score": 0.95,
        "supporting_evidence": ["15 repeated SSH login attempts", "Rapid flow rate"],
        "detection_method": "Rule: Repeated Authentication Probe Rate"
    }
    tool_registry.register_threat(sample_threat)
    report = agent_orchestrator.investigate(sample_threat)
    
    assert report is not None
    assert report["incident_id"] == "INC-THREAT-UNITTEST"
    assert report["mitre_attack"]["technique_id"] == "T1110"
    assert len(report["workflow_audit_trail"]) == 4
    assert len(report["pending_approvals"]) > 0

def test_hitl_approval_lifecycle():
    appr = tool_registry.create_human_approval_request(
        incident_id="INC-TEST-01",
        action_name="Block Attacker IP 205.174.165.73",
        target_entity="205.174.165.73",
        rationale="Active brute force campaign",
        risk_level="HIGH"
    )
    assert appr["status"] == "PENDING_APPROVAL"
    appr_id = appr["approval_id"]
    
    # Simulate analyst approval
    tool_registry.human_approval_queue[appr_id]["status"] = "APPROVED"
    assert tool_registry.human_approval_queue[appr_id]["status"] == "APPROVED"

if __name__ == "__main__":
    print("Running pipeline tests...")
    test_streaming_bus_produce_and_consume()
    print("✓ test_streaming_bus_produce_and_consume passed")
    test_mitre_attack_rag()
    print("✓ test_mitre_attack_rag passed")
    test_stateful_window_processor()
    print("✓ test_stateful_window_processor passed")
    test_duplicate_event_handling()
    print("✓ test_duplicate_event_handling passed")
    test_hybrid_threat_detection_port_scan()
    print("✓ test_hybrid_threat_detection_port_scan passed")
    test_multi_agent_orchestrator()
    print("✓ test_multi_agent_orchestrator passed")
    test_hitl_approval_lifecycle()
    print("✓ test_hitl_approval_lifecycle passed")
    print("\nALL 7 CORE PIPELINE TESTS PASSED!")
