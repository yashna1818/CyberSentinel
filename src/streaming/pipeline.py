import time
import logging
from typing import Dict, Any

from src.config import (
    TOPIC_SECURITY_LOGS,
    TOPIC_DETECTED_THREATS,
    TOPIC_SECURITY_ALERTS
)
from src.streaming.bus import stream_bus
from src.streaming.window_processor import StatefulWindowProcessor
from src.detection.engine import detection_engine
from src.agents.orchestrator import agent_orchestrator
from src.agents.tools import tool_registry
from src.streaming.metrics import stream_metrics

logger = logging.getLogger("StreamingPipeline")

class SecurityStreamPipeline:
    """
    Connects the streaming ingestion, stateful window processor,
    threat detection engine, and multi-agent AI orchestrator.
    """
    def __init__(self):
        self.window_processor = StatefulWindowProcessor()
        self.is_active = False

    def start(self):
        if self.is_active:
            return
        self.is_active = True
        
        # 1. Subscribe window processor & detection to TOPIC_SECURITY_LOGS
        stream_bus.subscribe(
            topic=TOPIC_SECURITY_LOGS,
            consumer_group="window-processor-group",
            callback=self._on_security_log_received
        )
        
        # 2. Subscribe multi-agent AI orchestrator to TOPIC_DETECTED_THREATS
        stream_bus.subscribe(
            topic=TOPIC_DETECTED_THREATS,
            consumer_group="agent-investigation-group",
            callback=self._on_threat_detected
        )
        
        logger.info("Security Stream Processing Pipeline active.")

    def _on_security_log_received(self, topic: str, event: Dict[str, Any]):
        # Keep ephemeral record for agent forensic retrieval
        tool_registry.register_event(event)
        
        # Process through stateful sliding window
        window_summary = self.window_processor.process_event(event)
        if window_summary:
            # Correlate window in hybrid threat detection engine
            detection_engine.analyze_window(window_summary)

    def _on_threat_detected(self, topic: str, threat: Dict[str, Any]):
        # Register threat in tool registry
        tool_registry.register_threat(threat)
        
        # Trigger Multi-Agent AI Investigation
        logger.info(f"Triggering Multi-Agent AI Investigation for {threat.get('threat_id')}...")
        report = agent_orchestrator.investigate(threat)
        
        # Publish final enriched alert
        stream_bus.produce(
            topic=TOPIC_SECURITY_ALERTS,
            value=report,
            key=threat.get("src_ip")
        )

# Global pipeline instance
security_pipeline = SecurityStreamPipeline()
