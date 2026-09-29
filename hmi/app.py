from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from gateway.khalid_gateway_hmi import (
    GatewayConfig,
    GatewayValidator,
    HashChainedAuditLog,
    SimulatedPLC,
    classify_command,
    make_command,
)


app = FastAPI(title="ChemShield Khalid HMI", version="1.0.0")

CONFIG = GatewayConfig()
AUDIT = HashChainedAuditLog()
PLC = SimulatedPLC()
GATEWAY = GatewayValidator(CONFIG, PLC, AUDIT)
SEQUENCE = {"value": 0}


def _next_sequence() -> int:
    SEQUENCE["value"] += 1
    return SEQUENCE["value"]


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>ChemShield Khalid HMI</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 24px; background:#f6f7f9; color:#18202a; }
        .grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
        .card { background:white; border-radius:12px; padding:16px; box-shadow:0 2px 10px rgba(0,0,0,.08); }
        label { display:block; margin-top:10px; font-weight:600; }
        input, select, button { padding:10px; margin-top:4px; width:100%; box-sizing:border-box; }
        button { cursor:pointer; border:0; border-radius:8px; background:#124f86; color:white; font-weight:700; margin-top:14px; }
        .status { font-size:28px; font-weight:800; }
        pre { white-space:pre-wrap; background:#111827; color:#e5e7eb; padding:12px; border-radius:8px; max-height:320px; overflow:auto; }
      </style>
    </head>
    <body>
      <h1>ChemShield Khalid HMI — SIM Mode</h1>
      <p>Operator screen for gateway decision, reason code, Model A result, HALT/ACK, attack counter, and audit log.</p>
      <div class="grid">
        <div class="card">
          <h2>Dose Request</h2>
          <label>Action</label><select id="action"><option>RECOVERY_DOSE</option><option>DOSE</option><option>HOLD</option></select>
          <label>Reagent</label><select id="reagent"><option>base</option><option>acid</option><option>none</option></select>
          <label>Volume mL</label><input id="volume" type="number" value="12" step="0.1">
          <label>Flow mL/min</label><input id="flow" type="number" value="300" step="1">
          <label>Mixing time s</label><input id="mixing" type="number" value="15" step="1">
          <button onclick="sendDose()">Send through Gateway</button>
          <button onclick="attackDemo()">Run Replay Attack Demo</button>
          <button onclick="halt()">HALT / SAFE_HOLD</button>
          <button onclick="ack()">ACK / Reset SIM</button>
        </div>
        <div class="card">
          <h2>Gateway Decision</h2>
          <div id="decision" class="status">Waiting</div>
          <p><b>Reason:</b> <span id="reason">—</span></p>
          <p><b>Forwarded to PLC:</b> <span id="forwarded">—</span></p>
          <p><b>Model A:</b> <span id="model">—</span></p>
          <p><b>Attack counter:</b> <span id="attacks">0</span></p>
          <p><b>System state:</b> <span id="state">NORMAL</span></p>
        </div>
      </div>
      <div class="card" style="margin-top:16px"><h2>Audit Log</h2><pre id="audit">[]</pre></div>
      <script>
        async function postJSON(url, body) {
          const res = await fetch(url, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body || {})});
          return await res.json();
        }
        function render(data) {
          document.getElementById("decision").textContent = data.decision || "—";
          document.getElementById("reason").textContent = data.reason_code || "—";
          document.getElementById("forwarded").textContent = data.forwarded_to_plc;
          document.getElementById("model").textContent = data.model_a ? `${data.model_a.label} / risk ${data.model_a.risk_score} / ${data.model_a.latency_ms} ms` : "—";
          document.getElementById("attacks").textContent = data.attack_counter ?? "0";
          document.getElementById("state").textContent = data.system_state || "NORMAL";
          loadAudit();
        }
        async function sendDose() {
          render(await postJSON("/api/submit-dose", {
            action:document.getElementById("action").value,
            reagent:document.getElementById("reagent").value,
            volume_ml:Number(document.getElementById("volume").value),
            flow_ml_min:Number(document.getElementById("flow").value),
            mixing_time_s:Number(document.getElementById("mixing").value)
          }));
        }
        async function attackDemo() { render(await postJSON("/api/replay-attack-demo", {})); }
        async function halt() { render(await postJSON("/api/halt", {})); }
        async function ack() { render(await postJSON("/api/ack", {})); }
        async function loadAudit() {
          const res = await fetch("/api/audit");
          document.getElementById("audit").textContent = JSON.stringify(await res.json(), null, 2);
        }
        loadAudit();
      </script>
    </body>
    </html>
    """


@app.post("/api/submit-dose")
def submit_dose(payload: dict[str, Any]) -> JSONResponse:
    now = datetime.now(timezone.utc)
    seq = _next_sequence()
    command = make_command(
        CONFIG,
        command_id=f"CMD-HMI-{uuid.uuid4().hex[:8]}",
        event_id=f"EVT-HMI-{uuid.uuid4().hex[:8]}",
        timestamp_utc=now,
        nonce=f"N-HMI-{uuid.uuid4().hex}",
        sequence_number=seq,
        action=str(payload.get("action", "RECOVERY_DOSE")),
        reagent=str(payload.get("reagent", "base")),
        volume_ml=float(payload.get("volume_ml", 12.0)),
        flow_ml_min=float(payload.get("flow_ml_min", 300.0)),
        mixing_time_s=float(payload.get("mixing_time_s", 15.0)),
    )
    model = classify_command(command)
    decision = GATEWAY.validate(command, "hmi_operator_command", now)
    return JSONResponse({**decision.__dict__, "model_a": model, "attack_counter": PLC.blocked_direct_writes, "system_state": "SAFE_HOLD" if GATEWAY.safe_hold_active else "NORMAL", "audit_chain_valid": AUDIT.verify()})


@app.post("/api/replay-attack-demo")
def replay_attack_demo() -> JSONResponse:
    now = datetime.now(timezone.utc)
    seq = _next_sequence()
    command = make_command(CONFIG, command_id=f"CMD-ATTACK-{uuid.uuid4().hex[:8]}", event_id="EVT-ATTACK-DEMO", timestamp_utc=now, nonce=f"N-ATTACK-{uuid.uuid4().hex}", sequence_number=seq)
    first = GATEWAY.validate(command, "hmi_attack_seed_valid", now)
    second = GATEWAY.validate(command, "hmi_replay_attack", now)
    return JSONResponse({**second.__dict__, "first_decision": first.decision, "model_a": classify_command(command), "attack_counter": PLC.blocked_direct_writes + 1, "system_state": "SAFE_HOLD" if GATEWAY.safe_hold_active else "NORMAL", "audit_chain_valid": AUDIT.verify()})


@app.post("/api/halt")
def halt() -> JSONResponse:
    GATEWAY.set_failure_state(safe_hold=True, heartbeat_healthy=False)
    return JSONResponse({"decision": "REJECT", "reason_code": "MANUAL_SAFE_HOLD", "forwarded_to_plc": False, "model_a": None, "attack_counter": PLC.blocked_direct_writes, "system_state": "SAFE_HOLD"})


@app.post("/api/ack")
def ack() -> JSONResponse:
    GATEWAY.manual_restart_with_new_session()
    return JSONResponse({"decision": "ACCEPT", "reason_code": "SIM_ACK_RESET", "forwarded_to_plc": False, "model_a": None, "attack_counter": PLC.blocked_direct_writes, "system_state": "NORMAL"})


@app.get("/api/audit")
def audit() -> JSONResponse:
    return JSONResponse({"audit_chain_valid": AUDIT.verify(), "records": AUDIT.tail(20)})
