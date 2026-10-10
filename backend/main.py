"""
SentinelAI FastAPI Core Application
High-performance REST API and real-time WebSocket ingestion & alert streaming gateway.
"""

import os
import json
import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.config import settings
from backend.database import db_manager
from backend.log_processor import log_processor
from backend.ml_engine import ml_engine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("sentinel_api")


class WebSocketHub:
    """Manages active WebSocket connections for log ingestion and live alerts."""

    def __init__(self):
        self.alert_subscribers: List[WebSocket] = []
        self.log_streamers: List[WebSocket] = []

    async def connect_alert_sub(self, ws: WebSocket):
        await ws.accept()
        self.alert_subscribers.append(ws)
        logger.info("New alert subscriber connected. Total: %d", len(self.alert_subscribers))

    def disconnect_alert_sub(self, ws: WebSocket):
        if ws in self.alert_subscribers:
            self.alert_subscribers.remove(ws)
            logger.info("Alert subscriber disconnected. Remaining: %d", len(self.alert_subscribers))

    async def broadcast_alert(self, alert_data: Dict[str, Any]):
        """Broadcast threat alerts to all connected dashboards."""
        if not self.alert_subscribers:
            return

        payload = json.dumps(alert_data, default=str)
        dead_connections = []
        for ws in self.alert_subscribers:
            try:
                await ws.send_text(payload)
            except Exception:
                dead_connections.append(ws)

        for dead in dead_connections:
            self.disconnect_alert_sub(dead)


ws_hub = WebSocketHub()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown life cycle management."""
    logger.info("Initializing SentinelAI Backend Engine...")
    await db_manager.connect()

    # Load ML Model
    loaded = ml_engine.load()
    if not loaded:
        logger.info("Model not found on disk. Checking default training set or operating with heuristics.")

    yield

    logger.info("Shutting down SentinelAI Backend...")
    await db_manager.close()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="SentinelAI: Real-Time Threat Detection & Log Analytics Platform",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================================================================
# Request/Response Schemas
# ==============================================================================

class LogEntryPayload(BaseModel):
    raw: Optional[str] = None
    client_ip: Optional[str] = "127.0.0.1"
    method: Optional[str] = "GET"
    path: Optional[str] = "/"
    status_code: Optional[int] = 200
    response_bytes: Optional[int] = 512
    user_agent: Optional[str] = "-"
    referer: Optional[str] = "-"
    payload: Optional[str] = ""
    timestamp: Optional[datetime] = None


class BatchLogIngestRequest(BaseModel):
    logs: List[LogEntryPayload]


class AlertAckRequest(BaseModel):
    acknowledged_by: str = Field(default="Security Analyst")


# ==============================================================================
# Ingestion & Prediction Logic Helper
# ==============================================================================

async def process_and_persist_log(log_raw_or_dict: Any) -> Dict[str, Any]:
    """Internal helper to parse, extract features, predict, and store."""
    parsed_log = log_processor.parse_raw_log(log_raw_or_dict)
    prediction = ml_engine.predict_single(parsed_log)

    enriched_log = {
        **parsed_log,
        "is_threat": prediction["is_threat"],
        "severity": prediction["severity"],
        "anomaly_score": prediction["decision_score"],
        "threat_category": prediction["threat_category"],
        "confidence": prediction["confidence"],
        "contributing_features": prediction["contributing_features"],
        "inference_latency_ms": prediction["latency_ms"],
    }

    log_id = await db_manager.insert_log(enriched_log)
    enriched_log["id"] = log_id

    # If classified as threat, construct and save threat alert
    if prediction["is_threat"]:
        alert = {
            "log_id": log_id,
            "timestamp": enriched_log["timestamp"],
            "client_ip": enriched_log["client_ip"],
            "severity": prediction["severity"],
            "threat_category": prediction["threat_category"],
            "anomaly_score": prediction["decision_score"],
            "path": enriched_log["path"],
            "method": enriched_log["method"],
            "country": enriched_log["country"],
            "city": enriched_log["city"],
            "contributing_features": prediction["contributing_features"],
            "acknowledged": False,
        }
        alert_id = await db_manager.insert_alert(alert)
        alert["id"] = alert_id

        # Real-time WebSocket push to dashboards
        asyncio.create_task(ws_hub.broadcast_alert(alert))

    return enriched_log


# ==============================================================================
# REST Endpoints
# ==============================================================================

@app.get("/health", tags=["Health"])
async def health_check():
    """System and component health diagnostic check."""
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "mongodb_connected": db_manager.is_connected,
        "model_trained": ml_engine.is_trained,
        "active_alert_websockets": len(ws_hub.alert_subscribers),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/v1/logs/ingest", tags=["Log Ingestion"])
async def ingest_single_log(payload: LogEntryPayload):
    """
    Ingest a single log line (raw string or structured fields),
    perform real-time ML inference, and alert if anomalous.
    """
    raw_data = payload.raw if payload.raw else payload.model_dump(exclude_unset=True)
    result = await process_and_persist_log(raw_data)
    return {
        "status": "success",
        "log_id": result.get("id"),
        "is_threat": result.get("is_threat"),
        "severity": result.get("severity"),
        "anomaly_score": result.get("anomaly_score"),
        "threat_category": result.get("threat_category"),
    }


@app.post("/api/v1/logs/ingest/batch", tags=["Log Ingestion"])
async def ingest_batch_logs(payload: BatchLogIngestRequest):
    """Ingest a batch of HTTP logs for high-throughput stream processing."""
    threat_count = 0
    results = []

    for item in payload.logs:
        raw_data = item.raw if item.raw else item.model_dump(exclude_unset=True)
        res = await process_and_persist_log(raw_data)
        if res.get("is_threat"):
            threat_count += 1
        results.append({
            "id": res.get("id"),
            "is_threat": res.get("is_threat"),
            "severity": res.get("severity")
        })

    return {
        "status": "success",
        "processed_count": len(results),
        "threats_detected": threat_count,
        "results": results
    }


@app.get("/api/v1/logs", tags=["Logs Query"])
async def query_logs(
    limit: int = Query(default=100, le=1000),
    skip: int = Query(default=0),
    threat_only: bool = Query(default=False),
    min_severity: Optional[str] = Query(default=None),
    ip: Optional[str] = Query(default=None)
):
    """Query ingested logs with filtering by threat status, severity, and IP."""
    logs = await db_manager.get_recent_logs(
        limit=limit, skip=skip, threat_only=threat_only, min_severity=min_severity, ip=ip
    )
    return {"count": len(logs), "logs": logs}


@app.get("/api/v1/alerts", tags=["Threat Alerts"])
async def query_alerts(
    limit: int = Query(default=50, le=500),
    acknowledged: Optional[bool] = Query(default=None),
    min_severity: Optional[str] = Query(default=None)
):
    """Fetch high-priority threat alerts."""
    alerts = await db_manager.get_recent_alerts(
        limit=limit, acknowledged=acknowledged, min_severity=min_severity
    )
    return {"count": len(alerts), "alerts": alerts}


@app.post("/api/v1/alerts/{alert_id}/acknowledge", tags=["Threat Alerts"])
async def acknowledge_alert(alert_id: str, payload: AlertAckRequest):
    """SOC Analyst endpoint to acknowledge/clear a security alert."""
    success = await db_manager.acknowledge_alert(alert_id, acknowledged_by=payload.acknowledged_by)
    if not success:
        raise HTTPException(status_code=404, detail="Alert ID not found or already acknowledged")
    return {"status": "acknowledged", "alert_id": alert_id, "by": payload.acknowledged_by}


@app.get("/api/v1/analytics/stats", tags=["Analytics & Metrics"])
async def get_overview_statistics(hours: int = Query(default=24, ge=1)):
    """Retrieve top-level KPI metrics for SIEM dashboard summary cards."""
    stats = await db_manager.get_threat_statistics(hours=hours)
    perf = ml_engine.get_performance_stats()
    stats["inference_performance"] = perf
    return stats


@app.get("/api/v1/analytics/top-ips", tags=["Analytics & Metrics"])
async def get_top_threat_ips(limit: int = Query(default=10, le=50)):
    """Retrieve top attacking client IP addresses and their origins."""
    top_ips = await db_manager.get_top_threat_ips(limit=limit)
    return {"top_ips": top_ips}


@app.get("/api/v1/analytics/severity-distribution", tags=["Analytics & Metrics"])
async def get_severity_distribution():
    """Retrieve aggregated counts for all severity classifications."""
    distribution = await db_manager.get_severity_distribution()
    return {"distribution": distribution}


@app.get("/api/v1/analytics/categories", tags=["Analytics & Metrics"])
async def get_attack_categories():
    """Retrieve breakdown of threat categories (SQLi, XSS, Scanners, etc.)."""
    categories = await db_manager.get_attack_category_breakdown()
    return {"categories": categories}


@app.get("/api/v1/analytics/timeline", tags=["Analytics & Metrics"])
async def get_hourly_timeline(hours: int = Query(default=24, ge=1)):
    """Hourly bucket distribution of requests and detected anomalies."""
    trend = await db_manager.get_hourly_threat_trend(hours=hours)
    return {"timeline": trend}


@app.get("/api/v1/analytics/geo", tags=["Analytics & Metrics"])
async def get_geo_threats():
    """Aggregated geographical locations of active threats for the Plotly threat map."""
    geo_data = await db_manager.get_geo_threat_map_data()
    return {"geo_points": geo_data}


@app.get("/api/v1/model/status", tags=["ML Engine"])
async def get_model_status():
    """Diagnostic details regarding the Isolation Forest model artifact & features."""
    return {
        "model_engine": ml_engine.get_performance_stats(),
        "feature_set": ml_engine.feature_names,
        "feature_count": len(ml_engine.feature_names),
        "thresholds": {
            "low": settings.SCORE_THRESHOLD_LOW,
            "medium": settings.SCORE_THRESHOLD_MEDIUM,
            "high": settings.SCORE_THRESHOLD_HIGH,
            "critical": settings.SCORE_THRESHOLD_CRITICAL,
        }
    }


# ==============================================================================
# WebSocket Endpoints
# ==============================================================================

@app.websocket("/ws/logs")
async def websocket_log_ingestion(websocket: WebSocket):
    """
    High-speed streaming WebSocket endpoint for continuous log ingestion.
    Clients can push Apache, Nginx, or JSON logs continuously.
    """
    await websocket.accept()
    logger.info("Log ingestion WebSocket connection established.")
    try:
        while True:
            data = await websocket.receive_text()
            try:
                try:
                    parsed = json.loads(data)
                except Exception:
                    parsed = data

                res = await process_and_persist_log(parsed)
                # Send confirmation / threat classification back to sender
                await websocket.send_text(json.dumps({
                    "status": "processed",
                    "id": res.get("id"),
                    "is_threat": res.get("is_threat"),
                    "severity": res.get("severity"),
                    "anomaly_score": res.get("anomaly_score")
                }))
            except Exception as e:
                await websocket.send_text(json.dumps({"error": str(e)}))
    except WebSocketDisconnect:
        logger.info("Log ingestion WebSocket client disconnected.")


@app.websocket("/ws/alerts")
async def websocket_alert_feed(websocket: WebSocket):
    """
    Real-time push feed for connected SOC analyst dashboards.
    Transmits threats instantly upon detection.
    """
    await ws_hub.connect_alert_sub(websocket)
    try:
        while True:
            # Keep-alive ping/pong
            _ = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_hub.disconnect_alert_sub(websocket)
