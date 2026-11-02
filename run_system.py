#!/usr/bin/env python3
"""
Aegis-Stream SOC Platform Launcher
Real-Time Cybersecurity Log Correlation with Multi-Agent AI
"""

import os
import sys
import uvicorn
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from src.config import API_HOST, API_PORT

if __name__ == "__main__":
    print("=" * 70)
    print(" AEGIS-STREAM SOC PLATFORM: REAL-TIME LOG CORRELATION & AGENTIC AI")
    print(" Dual Subject Focus: Stream Processing & Analytics (SPA) + Agentic AI")
    print(" Dataset: CIC-IDS2017 Comprehensive Network-Flow Benchmark")
    print("=" * 70)
    print(f" -> Web Dashboard:  http://localhost:{API_PORT}")
    print(f" -> WebSocket Feed: ws://localhost:{API_PORT}/ws/stream")
    print(f" -> REST API Docs:  http://localhost:{API_PORT}/docs")
    print("=" * 70)
    
    uvicorn.run(
        "src.api.server:app",
        host=API_HOST,
        port=API_PORT,
        log_level="info",
        reload=False
    )
