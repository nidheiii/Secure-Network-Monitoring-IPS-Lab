"""
FastAPI Server for Secure Network Monitoring & IPS Lab
Provides REST API, WebSockets for real-time live packet streaming and SOC alerting,
and serves the modern interactive web SOC dashboard.
"""

import os
import sys
import json
import asyncio
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.engine import LabEngine
from core.models import IPSMode
from core.syslog_server import start_syslog_listener

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
os.makedirs(WEB_DIR, exist_ok=True)

# Initialize Lab Engine
engine = LabEngine(base_dir=BASE_DIR)

# Background tasks
background_tasks = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start background traffic loop & syslog server
    traffic_task = asyncio.create_task(engine.start_background_loop())
    background_tasks.append(traffic_task)

    # Start Syslog receiver on UDP port 5140
    syslog_transport = await start_syslog_listener(
        port=5140,
        on_message=lambda msg: engine.wazuh.process_syslog(msg)
    )

    yield

    # Shutdown
    engine.stop_background_loop()
    for task in background_tasks:
        task.cancel()
    if syslog_transport:
        syslog_transport.close()


app = FastAPI(title="Secure Network Monitoring & IPS Lab", lifespan=lifespan)

# Active WebSocket connections
connected_websockets: List[WebSocket] = []


def websocket_broadcast(event: Dict[str, Any]):
    """Push event to all active WebSocket clients."""
    if not connected_websockets:
        return
    msg = json.dumps(event)
    for ws in list(connected_websockets):
        try:
            asyncio.create_task(ws.send_text(msg))
        except Exception:
            pass


# Hook engine broadcaster to WebSocket broadcaster
engine.subscribe(websocket_broadcast)


# Request Models
class ModeRequest(BaseModel):
    mode: str  # "IDS" or "IPS"


class AttackRequest(BaseModel):
    category: str  # "nmap" or "hydra"
    scenario: str  # "syn", "connect", "null", "fin", "xmas", "ack", "udp", "service", "os", "sweep", "ssh", "http", "rdp", "smb", "ftp"
    count: Optional[int] = None


class QuarantineRequest(BaseModel):
    ip: str
    reason: Optional[str] = "Manual SOC Quarantine"


class NormalTrafficRequest(BaseModel):
    enabled: bool


# API Endpoints
@app.get("/api/status")
async def get_status():
    return engine.get_status()


@app.post("/api/mode")
async def set_mode(req: ModeRequest):
    if req.mode.upper() == "IPS":
        engine.set_ips_mode(IPSMode.IPS)
    elif req.mode.upper() == "IDS":
        engine.set_ips_mode(IPSMode.IDS)
    else:
        raise HTTPException(status_code=400, detail="Mode must be 'IDS' or 'IPS'")
    return {"status": "ok", "mode": engine.suricata.mode.value}


@app.post("/api/attack")
async def trigger_attack(req: AttackRequest):
    asyncio.create_task(engine.run_attack_scenario(req.category.lower(), req.scenario.lower(), req.count or 0))
    return {
        "status": "launched",
        "category": req.category,
        "scenario": req.scenario
    }


@app.post("/api/quarantine/unblock")
async def unblock_ip(req: QuarantineRequest):
    success = engine.firewall.unblock_ip(req.ip)
    engine.broadcast_event({
        "type": "quarantine_released",
        "ip": req.ip,
        "timestamp": engine.metrics.current_attack_start
    })
    return {"status": "ok", "unblocked": success}


@app.post("/api/quarantine/block")
async def block_ip(req: QuarantineRequest):
    engine.firewall.quarantine_ip(req.ip, req.reason or "Manual Admin Ban", 999999)
    engine.broadcast_event({
        "type": "active_response_quarantine",
        "ip": req.ip,
        "reason": req.reason,
        "rule_id": 999999
    })
    return {"status": "ok", "blocked": True}


@app.post("/api/traffic/normal")
async def toggle_normal_traffic(req: NormalTrafficRequest):
    engine.baseline_traffic_active = req.enabled
    return {"status": "ok", "baseline_active": engine.baseline_traffic_active}


@app.get("/api/logs/fast")
async def get_fast_log(lines: int = 50):
    path = engine.suricata.fast_log_path
    if not os.path.exists(path):
        return {"lines": []}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
        return {"lines": [line.strip() for line in all_lines[-lines:]]}


@app.get("/api/logs/eve")
async def get_eve_log(limit: int = 50):
    path = engine.suricata.eve_log_path
    if not os.path.exists(path):
        return {"events": []}
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f.readlines()[-limit:]:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass
    return {"events": events}


@app.get("/api/logs/wazuh")
async def get_wazuh_alerts(limit: int = 50):
    path = engine.wazuh.alerts_json_path
    if not os.path.exists(path):
        return {"alerts": []}
    alerts = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f.readlines()[-limit:]:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except Exception:
                    pass
    return {"alerts": alerts}


@app.get("/api/rules")
async def get_rules():
    suricata_rules = []
    for r in engine.suricata.rules:
        suricata_rules.append({
            "sid": r.sid,
            "action": r.action,
            "proto": r.proto,
            "msg": r.msg,
            "classtype": r.classtype,
            "priority": r.priority,
            "threshold": f"{r.threshold_count} in {r.threshold_seconds}s"
        })
    return {
        "suricata_rules": suricata_rules,
        "firewall_policies": [
            {"id": 1, "name": "INET_TO_DMZ_HTTPS", "action": "Accept", "src": "WAN", "dst": "DMZ:443"},
            {"id": 2, "name": "USERS_TO_INET", "action": "Accept", "src": "USERS", "dst": "WAN (80/443/53)"},
            {"id": 3, "name": "MGMT_TO_SERVERS_SSH", "action": "Accept", "src": "MGMT", "dst": "SERVERS:22"},
            {"id": 4, "name": "DMZ_TO_SERVERS_APP", "action": "Accept", "src": "DMZ", "dst": "SERVERS"},
            {"id": 5, "name": "DENY_ALL_OTHER", "action": "Deny", "src": "any", "dst": "any"}
        ]
    }


# WebSocket Endpoint
@app.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)

    # Send initial snapshot state
    initial_payload = {
        "type": "init",
        "status": engine.get_status(),
        "recent_alerts": engine.recent_alerts[-20:],
        "recent_packets": engine.recent_packets[-15:]
    }
    await websocket.send_text(json.dumps(initial_payload))

    try:
        while True:
            data = await websocket.receive_text()
            try:
                cmd = json.loads(data)
                action = cmd.get("action")
                if action == "attack":
                    cat = cmd.get("category", "nmap")
                    scen = cmd.get("scenario", "syn")
                    cnt = cmd.get("count", 0)
                    asyncio.create_task(engine.run_attack_scenario(cat, scen, cnt))
                elif action == "mode":
                    mode_str = cmd.get("mode", "IDS")
                    engine.set_ips_mode(IPSMode.IPS if mode_str == "IPS" else IPSMode.IDS)
                elif action == "unblock":
                    engine.firewall.unblock_ip(cmd.get("ip"))
                elif action == "block":
                    engine.firewall.quarantine_ip(cmd.get("ip"), "Manual Ban", 999999)
            except Exception:
                pass
    except WebSocketDisconnect:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)


# Static and Web Frontend Routes
@app.get("/")
async def serve_index():
    index_path = os.path.join(WEB_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>Secure Network Monitoring & IPS Lab</h1><p>Web dashboard is loading...</p>")


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
