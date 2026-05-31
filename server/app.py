"""
switch-pctltcp-remote — Server-side API

Lightweight FastAPI service for Switch remote parental control.
Receives heartbeat from Switch, queues commands for delivery.

Endpoints:
  POST /heartbeat       — Switch heartbeat (PSK_SWITCH auth)
  POST /admin/command   — Admin push command (PSK_ADMIN auth)
  GET  /admin/status    — Admin check status (PSK_ADMIN auth)

Security:
  - Dual Bearer token authentication
  - Path whitelist enforced by 雷池 WAF
  - Rate limiting recommended at WAF level
"""

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from collections import deque
from datetime import datetime
import os

app = FastAPI(title="Switch Parental Control Remote API", version="1.0.0")

# ---------------------------------------------------------------------------
# Configuration — override via environment variables
# ---------------------------------------------------------------------------
PSK_SWITCH = os.environ.get("PSK_SWITCH", "sw-change-me-to-a-long-random-string")
PSK_ADMIN  = os.environ.get("PSK_ADMIN",  "adm-change-me-to-another-random-string")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
pending_commands: deque = deque(maxlen=10)
last_seen: dict = {"time": None, "ip": None, "version": ""}
cmd_counter: int = 0


def _check_auth(authorization: str | None, expected_token: str) -> None:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing authorization header")
    if authorization != f"Bearer {expected_token}":
        raise HTTPException(status_code=401, detail="unauthorized")


def _next_cmd_id() -> str:
    global cmd_counter
    cmd_counter += 1
    return f"cmd-{cmd_counter:04d}"


# ---------------------------------------------------------------------------
# Switch endpoints
# ---------------------------------------------------------------------------
class HeartbeatRequest(BaseModel):
    uptime: int = 0
    version: str = ""


@app.post("/heartbeat")
def heartbeat(
    body: HeartbeatRequest,
    authorization: str = Header(None),
    x_forwarded_for: str = Header(None),
    x_real_ip: str = Header(None),
):
    _check_auth(authorization, PSK_SWITCH)

    last_seen["time"] = datetime.now().isoformat()
    last_seen["ip"] = x_real_ip or x_forwarded_for or "unknown"
    last_seen["version"] = body.version

    if pending_commands:
        cmd = pending_commands.popleft()
        return {"status": "ok", "command": cmd}

    return {"status": "ok", "command": None}


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------
class CommandPush(BaseModel):
    action: str       # "add_minutes" | "set_day_limit" | "reset_play_time"
    value: int = 0


@app.post("/admin/command")
def push_command(body: CommandPush, authorization: str = Header(None)):
    _check_auth(authorization, PSK_ADMIN)

    valid_actions = {"add_minutes", "set_day_limit", "reset_play_time"}
    if body.action not in valid_actions:
        raise HTTPException(status_code=400, detail=f"invalid action: {body.action}")

    cmd = {
        "action": body.action,
        "value": body.value,
        "cmd_id": _next_cmd_id(),
    }
    pending_commands.append(cmd)
    return {"status": "ok", "queued": len(pending_commands), "cmd_id": cmd["cmd_id"]}


@app.get("/admin/status")
def status(authorization: str = Header(None)):
    _check_auth(authorization, PSK_ADMIN)
    return {
        "switch_last_seen": last_seen,
        "pending_commands": list(pending_commands),
        "pending_count": len(pending_commands),
    }


# ---------------------------------------------------------------------------
# Health check (no auth — for Docker healthcheck / load balancer)
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}
