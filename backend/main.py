import asyncio
import queue
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

import ownership
from models import Finding, LogEvent, PHASES
from report.report_generator import render_report
from scanners import (
    tls_scanner, http_headers_scanner, session_scanner,
    injection_scanner, access_control_scanner, external_tools,
)

app = FastAPI(title="VAShield Orchestrator")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

SESSIONS: dict[str, dict] = {}


class InjectionTarget(BaseModel):
    url: str
    param: str
    method: str = "GET"


class StartScanRequest(BaseModel):
    target_url: str
    ports: str = "443,80"
    profile: str = "baseline_staging"
    jwt_token: Optional[str] = None
    intrusive: bool = False
    auth_check_endpoint: Optional[str] = None
    injection_targets: list[InjectionTarget] = []
    bola_resource_template: Optional[str] = None
    tenant_a_token: Optional[str] = None
    tenant_b_object_id: Optional[str] = None
    admin_only_url: Optional[str] = None
    low_priv_token: Optional[str] = None
    source_path_for_sast: Optional[str] = None


@app.post("/api/v1/ownership/request-token")
def request_token(target_url: str):
    host = urlparse(target_url).hostname
    if not host:
        raise HTTPException(400, "Invalid target_url")
    token = ownership.generate_token(host)
    return {
        "host": host,
        "token": token,
        "instructions": f"Publish this token so that GET http://{host}/.well-known/security-check.txt "
                         f"returns a 200 response whose body contains: {token}",
    }


@app.post("/api/v1/assessments/start")
def start_assessment(req: StartScanRequest):
    ok, note = ownership.verify_ownership(req.target_url)
    if not ok:
        raise HTTPException(403, f"Ownership verification failed: {note}")

    session_id = str(uuid.uuid4())[:8]
    q: "queue.Queue" = queue.Queue()
    SESSIONS[session_id] = {
        "session_id": session_id,
        "target": req.target_url,
        "ports": req.ports,
        "profile": req.profile,
        "intrusive": req.intrusive,
        "ownership_note": note,
        "queue": q,
        "findings": [],
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }

    thread = threading.Thread(target=_run_pipeline, args=(session_id, req), daemon=True)
    thread.start()
    return {"session_id": session_id, "ownership_note": note, "phases": PHASES}


def _run_pipeline(session_id: str, req: StartScanRequest):
    session = SESSIONS[session_id]
    q = session["queue"]

    def log(level, message, phase_id=None):
        q.put(("log", LogEvent(level=level, message=message, phase_id=phase_id).to_dict()))

    def add_finding(finding: Finding):
        d = finding.to_dict()
        session["findings"].append(d)
        q.put(("finding", d))

    parsed = urlparse(req.target_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        q.put(("phase_start", {"phase_id": "phase-1"}))
        tls_scanner.run(host, port, log, add_finding)
        q.put(("phase_done", {"phase_id": "phase-1"}))

        q.put(("phase_start", {"phase_id": "phase-2"}))
        http_headers_scanner.run(req.target_url, log, add_finding)
        q.put(("phase_done", {"phase_id": "phase-2"}))

        q.put(("phase_start", {"phase_id": "phase-3"}))
        session_scanner.run(req.target_url, req.jwt_token, req.intrusive, req.auth_check_endpoint, log, add_finding)
        q.put(("phase_done", {"phase_id": "phase-3"}))

        q.put(("phase_start", {"phase_id": "phase-4"}))
        injection_scanner.run([t.dict() for t in req.injection_targets], log, add_finding)
        q.put(("phase_done", {"phase_id": "phase-4"}))

        q.put(("phase_start", {"phase_id": "phase-5"}))
        access_control_scanner.run(
            req.bola_resource_template, req.tenant_a_token, req.tenant_b_object_id,
            req.admin_only_url, req.low_priv_token, log, add_finding,
        )
        q.put(("phase_done", {"phase_id": "phase-5"}))

        q.put(("phase_start", {"phase_id": "phase-6"}))
        external_tools.run(host, req.ports, req.source_path_for_sast, log, add_finding)
        q.put(("phase_done", {"phase_id": "phase-6"}))

        session["status"] = "completed"
        q.put(("complete", {"total_findings": len(session["findings"])}))
    except Exception as e:
        session["status"] = "error"
        q.put(("log", LogEvent(level="CRIT", message=f"Orchestrator error: {e}").to_dict()))
        q.put(("complete", {"total_findings": len(session["findings"]), "error": str(e)}))


@app.get("/api/v1/scans/{session_id}/stream")
async def stream(session_id: str):
    if session_id not in SESSIONS:
        raise HTTPException(404, "Unknown session")
    q = SESSIONS[session_id]["queue"]

    async def event_gen():
        while True:
            try:
                kind, payload = await asyncio.get_event_loop().run_in_executor(None, q.get, True, 30)
            except Exception:
                if SESSIONS[session_id]["status"] != "running":
                    break
                yield ": keepalive\n\n"
                continue
            import json
            yield f"event: {kind}\ndata: {json.dumps(payload)}\n\n"
            if kind == "complete":
                break

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@app.get("/api/v1/scans/{session_id}/findings")
def get_findings(session_id: str):
    if session_id not in SESSIONS:
        raise HTTPException(404, "Unknown session")
    return {"findings": SESSIONS[session_id]["findings"], "status": SESSIONS[session_id]["status"]}


@app.get("/api/v1/scans/{session_id}/report", response_class=HTMLResponse)
def get_report(session_id: str):
    if session_id not in SESSIONS:
        raise HTTPException(404, "Unknown session")
    session = SESSIONS[session_id]
    html = render_report(session, session["findings"], PHASES)
    return HTMLResponse(content=html)


@app.get("/api/v1/phases")
def get_phases():
    return {"phases": PHASES}


@app.get("/health")
def health():
    return {"status": "ok"}
