import time
import threading
from typing import Dict, Any

class StreamMetrics:
    """
    Real-time performance metrics collector for Stream Processing and Analytics (SPA).
    Tracks throughput, latencies, consumer lag, and event counters.
    """
    def __init__(self):
        self._lock = threading.Lock()
        
        # Counters
        self.total_events_produced = 0
        self.total_events_consumed = 0
        self.total_threats_detected = 0
        self.total_alerts_generated = 0
        self.total_dropped_events = 0
        self.total_duplicate_events = 0
        self.total_processing_errors = 0
        
        # Rates & Windows
        self._last_calc_time = time.time()
        self._last_consumed_count = 0
        self._last_produced_count = 0
        self.producer_eps = 0.0
        self.consumer_eps = 0.0
        
        # Latencies (in milliseconds)
        self.avg_event_processing_latency_ms = 0.0
        self.avg_window_processing_time_ms = 0.0
        self.avg_detection_latency_ms = 0.0
        self.avg_end_to_end_latency_ms = 0.0
        
        # Latency accumulators for EMA (Exponential Moving Average)
        self._alpha = 0.1
        
        # Consumer Lag & Partitions
        self.consumer_lag = 0
        self.active_partitions = 3
        
        # Agent Investigation Latency
        self.avg_agent_investigation_latency_ms = 0.0

    def record_produced(self, count: int = 1):
        with self._lock:
            self.total_events_produced += count

    def record_consumed(self, count: int = 1, lag: int = 0):
        with self._lock:
            self.total_events_consumed += count
            self.consumer_lag = max(0, lag)

    def record_threat(self, count: int = 1):
        with self._lock:
            self.total_threats_detected += count

    def record_alert(self, count: int = 1):
        with self._lock:
            self.total_alerts_generated += count

    def record_dropped(self):
        with self._lock:
            self.total_dropped_events += 1

    def record_duplicate(self):
        with self._lock:
            self.total_duplicate_events += 1

    def record_error(self):
        with self._lock:
            self.total_processing_errors += 1

    def update_processing_latency(self, latency_ms: float):
        with self._lock:
            if self.avg_event_processing_latency_ms == 0.0:
                self.avg_event_processing_latency_ms = latency_ms
            else:
                self.avg_event_processing_latency_ms = (
                    (1 - self._alpha) * self.avg_event_processing_latency_ms + self._alpha * latency_ms
                )

    def update_window_latency(self, latency_ms: float):
        with self._lock:
            if self.avg_window_processing_time_ms == 0.0:
                self.avg_window_processing_time_ms = latency_ms
            else:
                self.avg_window_processing_time_ms = (
                    (1 - self._alpha) * self.avg_window_processing_time_ms + self._alpha * latency_ms
                )

    def update_detection_latency(self, latency_ms: float):
        with self._lock:
            if self.avg_detection_latency_ms == 0.0:
                self.avg_detection_latency_ms = latency_ms
            else:
                self.avg_detection_latency_ms = (
                    (1 - self._alpha) * self.avg_detection_latency_ms + self._alpha * latency_ms
                )

    def update_end_to_end_latency(self, latency_ms: float):
        with self._lock:
            if self.avg_end_to_end_latency_ms == 0.0:
                self.avg_end_to_end_latency_ms = latency_ms
            else:
                self.avg_end_to_end_latency_ms = (
                    (1 - self._alpha) * self.avg_end_to_end_latency_ms + self._alpha * latency_ms
                )

    def update_agent_latency(self, latency_ms: float):
        with self._lock:
            if self.avg_agent_investigation_latency_ms == 0.0:
                self.avg_agent_investigation_latency_ms = latency_ms
            else:
                self.avg_agent_investigation_latency_ms = (
                    (1 - self._alpha) * self.avg_agent_investigation_latency_ms + self._alpha * latency_ms
                )

    def snapshot(self) -> Dict[str, Any]:
        """Calculates instantaneous rates and returns a JSON-serializable snapshot"""
        with self._lock:
            now = time.time()
            dt = now - self._last_calc_time
            if dt >= 1.0:
                self.producer_eps = round((self.total_events_produced - self._last_produced_count) / dt, 1)
                self.consumer_eps = round((self.total_events_consumed - self._last_consumed_count) / dt, 1)
                self._last_calc_time = now
                self._last_produced_count = self.total_events_produced
                self._last_consumed_count = self.total_events_consumed
                
            return {
                "total_events_produced": self.total_events_produced,
                "total_events_consumed": self.total_events_consumed,
                "total_threats_detected": self.total_threats_detected,
                "total_alerts_generated": self.total_alerts_generated,
                "total_dropped_events": self.total_dropped_events,
                "total_duplicate_events": self.total_duplicate_events,
                "total_processing_errors": self.total_processing_errors,
                "producer_eps": self.producer_eps,
                "consumer_eps": self.consumer_eps,
                "consumer_lag": self.consumer_lag,
                "active_partitions": self.active_partitions,
                "event_processing_latency_ms": round(self.avg_event_processing_latency_ms, 2),
                "window_processing_time_ms": round(self.avg_window_processing_time_ms, 2),
                "detection_latency_ms": round(self.avg_detection_latency_ms, 2),
                "end_to_end_latency_ms": round(self.avg_end_to_end_latency_ms, 2),
                "agent_investigation_latency_ms": round(self.avg_agent_investigation_latency_ms, 2),
                "timestamp": now
            }

# Global singleton metrics instance
stream_metrics = StreamMetrics()
