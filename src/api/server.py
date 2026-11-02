import os
import time
import json
import asyncio
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.config import WORKSPACE_ROOT
from src.streaming.producer import stream_producer
from src.streaming.pipeline import security_pipeline
from src.streaming.bus import stream_bus
from src.streaming.metrics import stream_metrics
from src.agents.tools import tool_registry
from src.agents.orchestrator import agent_orchestrator
from src.agents.rag import mitre_rag

logger = logging.getLogger("SOCServer")

app = FastAPI(title="Real-Time Cybersecurity SOC Platform", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DASHBOARD_DIR = WORKSPACE_ROOT / "src" / "dashboard"

# Active WebSocket clients
connected_clients: List[WebSocket] = []

# Buffer for live event broadcast
recent_events_cache: List[Dict[str, Any]] = []
recent_threats_cache: List[Dict[str, Any]] = []
recent_investigations_cache: List[Dict[str, Any]] = []

def on_security_log_for_ws(topic: str, event: Dict[str, Any]):
    recent_events_cache.append(event)
    if len(recent_events_cache) > 200:
        recent_events_cache.pop(0)

def on_threat_detected_for_ws(topic: str, threat: Dict[str, Any]):
    recent_threats_cache.append(threat)
    if len(recent_threats_cache) > 50:
        recent_threats_cache.pop(0)

def on_security_alert_for_ws(topic: str, alert: Dict[str, Any]):
    recent_investigations_cache.append(alert)
    if len(recent_investigations_cache) > 50:
        recent_investigations_cache.pop(0)

@app.on_event("startup")
async def startup_event():
    # Start the stream processing pipeline
    security_pipeline.start()
    
    # Subscribe WS listener hooks to streaming bus
    stream_bus.subscribe("security-logs", "ws-logs-monitor", on_security_log_for_ws)
    stream_bus.subscribe("detected-threats", "ws-threats-monitor", on_threat_detected_for_ws)
    stream_bus.subscribe("security-alerts", "ws-alerts-monitor", on_security_alert_for_ws)
    
    # Start producer by default at realistic 50 EPS
    stream_producer.start()
    logger.info("FastAPI SOC Server initialized successfully.")

# WebSocket for real-time telemetry and push updates
@app.websocket("/ws/stream")
async def websocket_stream_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            # Gather state snapshot
            metrics = stream_metrics.snapshot()
            
            # Extract latest unbroadcasted batch
            events_batch = list(recent_events_cache[-15:])
            threats_batch = list(recent_threats_cache[-8:])
            investigations_batch = list(recent_investigations_cache[-5:])
            pending_approvals = list(tool_registry.human_approval_queue.values())
            
            payload = {
                "type": "TELEMETRY_UPDATE",
                "metrics": metrics,
                "events": events_batch,
                "threats": threats_batch,
                "investigations": investigations_batch,
                "pending_approvals": pending_approvals,
                "producer_status": {
                    "is_running": stream_producer.is_running,
                    "is_paused": stream_producer.is_paused,
                    "target_eps": stream_producer.target_eps
                }
            }
            
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(0.5) # 500ms broadcast cycle
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
    except Exception as e:
        if websocket in connected_clients:
            connected_clients.remove(websocket)

# REST API Models
class SpeedUpdateRequest(BaseModel):
    eps: float

class ApprovalActionRequest(BaseModel):
    action: str # "APPROVE" or "REJECT"
    analyst_notes: Optional[str] = "Approved by SOC Lead Analyst"

@app.get("/api/metrics")
def get_metrics():
    return stream_metrics.snapshot()

@app.get("/api/incidents")
def get_incidents():
    return agent_orchestrator.incident_history

@app.get("/api/approvals/pending")
def get_pending_approvals():
    return list(tool_registry.human_approval_queue.values())

@app.post("/api/approvals/{approval_id}/action")
def process_approval(approval_id: str, req: ApprovalActionRequest):
    if approval_id not in tool_registry.human_approval_queue:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    item = tool_registry.human_approval_queue[approval_id]
    item["status"] = "APPROVED" if req.action.upper() == "APPROVE" else "REJECTED"
    item["analyst_notes"] = req.analyst_notes
    item["resolved_at"] = time.time()
    
    return {"status": "SUCCESS", "approval_item": item}

@app.post("/api/stream/start")
def start_stream():
    stream_producer.start()
    return {"status": "STARTED", "eps": stream_producer.target_eps}

@app.post("/api/stream/pause")
def pause_stream():
    stream_producer.pause()
    return {"status": "PAUSED"}

@app.post("/api/stream/resume")
def resume_stream():
    stream_producer.resume()
    return {"status": "RESUMED"}

@app.post("/api/stream/stop")
def stop_stream():
    stream_producer.stop()
    return {"status": "STOPPED"}

@app.post("/api/stream/speed")
def update_stream_speed(req: SpeedUpdateRequest):
    stream_producer.set_speed(req.eps)
    return {"status": "UPDATED", "target_eps": stream_producer.target_eps}

@app.get("/api/mitre")
def get_mitre_techniques():
    return mitre_rag.techniques

# Serve Dashboard static files
if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")

@app.get("/")
def serve_dashboard():
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return JSONResponse({"message": "Dashboard HTML under development"})
