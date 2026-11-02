import time
import logging
from collections import defaultdict, deque
from typing import Dict, Any, List, Tuple, Optional, Callable
from datetime import datetime, timezone

from src.config import (
    DEFAULT_WINDOW_SIZE_SECONDS,
    DEFAULT_SLIDE_INTERVAL_SECONDS,
    LATE_ARRIVAL_TOLERANCE_SECONDS
)
from src.streaming.metrics import stream_metrics

logger = logging.getLogger("WindowProcessor")

class EventWindow:
    """Holds state and statistics for events grouped by key in a sliding time window"""
    def __init__(self, key: Tuple, window_start: float):
        self.key = key
        self.window_start = window_start
        self.events: List[Dict[str, Any]] = []

    def add_event(self, event: Dict[str, Any]):
        self.events.append(event)

    def compute_summary(self, current_time: float) -> Dict[str, Any]:
        count = len(self.events)
        if count == 0:
            return {}

        src_ip, dst_ip, proto, dst_port = self.key
        
        # Aggregate statistics
        total_packets = 0
        total_bytes = 0
        syn_count = 0
        fin_count = 0
        rst_count = 0
        short_duration_count = 0
        target_ports = set()
        
        for ev in self.events:
            total_packets += int(ev.get("Total Fwd Packets", 1) + ev.get("Total Backward Packets", 0))
            total_bytes += int(ev.get("Fwd Packets Length Total", 0) + ev.get("Bwd Packets Length Total", 0))
            syn_count += int(ev.get("SYN Flag Count", 0))
            fin_count += int(ev.get("FIN Flag Count", 0))
            rst_count += int(ev.get("RST Flag Count", 0))
            if float(ev.get("Flow Duration", 0)) < 100000: # < 100ms
                short_duration_count += 1
            target_ports.add(ev.get("dst_port", dst_port))

        duration_sec = max(0.1, current_time - self.window_start)
        
        return {
            "window_key": f"{src_ip}->{dst_ip}:{dst_port}(proto={proto})",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto,
            "dst_port": dst_port,
            "distinct_target_ports": list(target_ports),
            "num_distinct_ports": len(target_ports),
            "event_count": count,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "packets_per_sec": round(total_packets / duration_sec, 2),
            "bytes_per_sec": round(total_bytes / duration_sec, 2),
            "syn_count": syn_count,
            "fin_count": fin_count,
            "rst_count": rst_count,
            "short_duration_count": short_duration_count,
            "window_start": self.window_start,
            "window_end": current_time,
            "event_ids": [ev.get("event_id") for ev in self.events[-20:]], # keep last 20 IDs for evidence
            "latest_event": self.events[-1]
        }

class StatefulWindowProcessor:
    """
    Manages stateful sliding and tumbling windows over network flow event streams.
    Handles duplicate detection, late-arriving events, and window triggers.
    """
    def __init__(
        self,
        window_size_sec: float = DEFAULT_WINDOW_SIZE_SECONDS,
        slide_interval_sec: float = DEFAULT_SLIDE_INTERVAL_SECONDS,
        late_tolerance_sec: float = LATE_ARRIVAL_TOLERANCE_SECONDS
    ):
        self.window_size_sec = window_size_sec
        self.slide_interval_sec = slide_interval_sec
        self.late_tolerance_sec = late_tolerance_sec
        
        # State stores: key -> deque of events
        self.flow_windows: Dict[Tuple, deque] = defaultdict(deque)
        # Host-level state store: src_ip -> deque of events (for port scanning & distributed flood)
        self.host_windows: Dict[str, deque] = defaultdict(deque)
        
        # Bounded cache for deduplication
        self.seen_events = deque(maxlen=20000)
        self.seen_events_set = set()
        
        # Watermark
        self.current_watermark = 0.0
        self.on_window_trigger: Optional[Callable[[Dict[str, Any]], None]] = None

    def process_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        t_start = time.time()
        
        # 1. Duplicate check
        event_id = event.get("event_id")
        if event_id:
            if event_id in self.seen_events_set:
                stream_metrics.record_duplicate()
                return None
            self.seen_events_set.add(event_id)
            self.seen_events.append(event_id)
            if len(self.seen_events) >= 20000:
                # keep set in sync with bounded deque
                self.seen_events_set = set(self.seen_events)

        # 2. Event-time extraction
        ts_str = event.get("timestamp")
        try:
            event_time = datetime.fromisoformat(ts_str).timestamp()
        except Exception:
            event_time = time.time()

        # 3. Late arrival handling
        if self.current_watermark > 0 and (self.current_watermark - event_time) > self.late_tolerance_sec:
            stream_metrics.record_dropped()
            return None

        if event_time > self.current_watermark:
            self.current_watermark = event_time

        # 4. State store insertion
        src_ip = event.get("src_ip", "0.0.0.0")
        dst_ip = event.get("dst_ip", "0.0.0.0")
        proto = event.get("protocol", 6)
        dst_port = event.get("dst_port", 80)
        
        flow_key = (src_ip, dst_ip, proto, dst_port)
        
        # Append tuple of (event_time, event)
        self.flow_windows[flow_key].append((event_time, event))
        self.host_windows[src_ip].append((event_time, event))
        
        # 5. Evict events outside current window
        cutoff_time = event_time - self.window_size_sec
        
        flow_q = self.flow_windows[flow_key]
        while flow_q and flow_q[0][0] < cutoff_time:
            flow_q.popleft()
            
        host_q = self.host_windows[src_ip]
        while host_q and host_q[0][0] < cutoff_time:
            host_q.popleft()

        # 6. Aggregate window stats
        window = EventWindow(flow_key, cutoff_time)
        for _, ev in flow_q:
            window.add_event(ev)
            
        summary = window.compute_summary(event_time)
        
        # Enrich with host-level sweep metrics (across all destination ports)
        host_distinct_ports = {ev[1].get("dst_port") for ev in host_q}
        summary["host_distinct_ports_contacted"] = len(host_distinct_ports)
        summary["host_total_events_in_window"] = len(host_q)
        
        proc_ms = (time.time() - t_start) * 1000.0
        stream_metrics.update_window_latency(proc_ms)
        
        return summary
