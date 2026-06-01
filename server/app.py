"""
switch-pctltcp-remote — Server-side API

Lightweight FastAPI service for Switch remote parental control.
Receives heartbeat from Switch, queues commands for delivery.

Endpoints:
  GET  /                  — Admin web dashboard (requires ?key=PSK_ADMIN)
  POST /heartbeat         — Switch heartbeat (PSK_SWITCH auth)
  POST /admin/command     — Admin push command (PSK_ADMIN auth)
  GET  /admin/status      — Admin check status (PSK_ADMIN auth)

Security:
  - Dual Bearer token authentication
  - Dashboard requires admin key in URL parameter (?key=xxx)
  - Path whitelist enforced by 雷池 WAF
  - Rate limiting recommended at WAF level
"""

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from collections import deque
from datetime import datetime
import ipaddress
import os

app = FastAPI(title="Switch Parental Control Remote API", version="1.3.0")

# ---------------------------------------------------------------------------
# Configuration — override via environment variables
# ---------------------------------------------------------------------------
PSK_SWITCH = os.environ.get("PSK_SWITCH", "sw-change-me-to-a-long-random-string")
PSK_ADMIN  = os.environ.get("PSK_ADMIN",  "adm-change-me-to-another-random-string")

# LAN subnet — requests from this network skip the key check for dashboard
# Set to your home network, e.g. "192.168.1.0/24" or "10.0.0.0/8"
# Multiple networks: separate with comma, e.g. "192.168.1.0/24,10.0.0.0/8"
LAN_SUBNETS_STR = os.environ.get("LAN_SUBNETS", "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12")

def _parse_subnets(raw: str) -> list:
    """Parse comma-separated CIDR strings into ipaddress network objects."""
    nets = []
    for s in raw.split(","):
        s = s.strip()
        if not s:
            continue
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            pass
    return nets

LAN_SUBNETS = _parse_subnets(LAN_SUBNETS_STR)


def _is_lan_ip(ip_str: str) -> bool:
    """Check if an IP address belongs to any LAN subnet."""
    if not ip_str or ip_str == "unknown":
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        for net in LAN_SUBNETS:
            if addr in net:
                return True
    except ValueError:
        pass
    return False

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
# Admin web dashboard (single-page, self-contained)
# Protected by ?key=PSK_ADMIN URL parameter
# ---------------------------------------------------------------------------
FORBIDDEN_HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>403</title>
<style>
body{display:flex;justify-content:center;align-items:center;min-height:100vh;
  font-family:-apple-system,sans-serif;background:#f0f2f5;color:#888}
.box{text-align:center}
h1{font-size:72px;color:#d9d9d9;margin:0}
p{font-size:16px;margin-top:8px}
</style></head><body>
<div class="box"><h1>403</h1><p>Access denied</p></div>
</body></html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Switch Parental Control</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:#f0f2f5;min-height:100vh;padding:16px}
.card{background:#fff;border-radius:12px;padding:20px;margin-bottom:16px;
  box-shadow:0 1px 3px rgba(0,0,0,.1)}
h1{font-size:20px;margin-bottom:4px}
.subtitle{color:#666;font-size:13px;margin-bottom:16px}
.status-row{display:flex;justify-content:space-between;padding:8px 0;
  border-bottom:1px solid #f0f0f0;font-size:14px}
.status-row:last-child{border-bottom:none}
.status-label{color:#888}
.status-value{font-weight:500}
.online{color:#52c41a}.offline{color:#ff4d4f}
.btn-group{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px}
.btn{padding:14px 8px;border:none;border-radius:8px;font-size:15px;
  font-weight:500;cursor:pointer;transition:opacity .15s}
.btn:active{opacity:.7}
.btn-green{background:#52c41a;color:#fff}
.btn-blue{background:#1890ff;color:#fff}
.btn-orange{background:#fa8c16;color:#fff}
.btn-red{background:#ff4d4f;color:#fff}
.input-group{margin-top:12px}
.input-group label{display:block;font-size:13px;color:#666;margin-bottom:4px}
.input-group input{width:100%;padding:10px;border:1px solid #d9d9d9;
  border-radius:6px;font-size:16px;outline:none}
.input-group input:focus{border-color:#1890ff}
.log{font-size:12px;color:#888;max-height:120px;overflow-y:auto;
  padding:8px;background:#fafafa;border-radius:6px;margin-top:8px}
.log-entry{padding:2px 0;border-bottom:1px solid #f0f0f0}
.toast{position:fixed;top:20px;left:50%;transform:translateX(-50%);
  padding:10px 24px;border-radius:8px;color:#fff;font-size:14px;
  z-index:999;opacity:0;transition:opacity .3s}
.toast.show{opacity:1}
.toast-ok{background:#52c41a}.toast-err{background:#ff4d4f}
</style>
</head>
<body>
<div id="toast" class="toast"></div>

<div class="card">
  <h1>Switch Parental Control</h1>
  <p class="subtitle">Remote management dashboard</p>
  <div class="status-row">
    <span class="status-label">Switch status</span>
    <span id="sw-status" class="status-value offline">Offline</span>
  </div>
  <div class="status-row">
    <span class="status-label">Last heartbeat</span>
    <span id="sw-time" class="status-value">--</span>
  </div>
  <div class="status-row">
    <span class="status-label">Pending commands</span>
    <span id="sw-pending" class="status-value">0</span>
  </div>
</div>

<div class="card">
  <h1>Quick actions</h1>
  <p class="subtitle">One-click time control</p>
  <div class="btn-group">
    <button class="btn btn-green" onclick="sendCmd('add_minutes',30)">+30 min</button>
    <button class="btn btn-green" onclick="sendCmd('add_minutes',60)">+60 min</button>
    <button class="btn btn-blue" onclick="sendCmd('add_minutes',120)">+2 hours</button>
    <button class="btn btn-blue" onclick="sendCmd('add_minutes',180)">+3 hours</button>
  </div>
  <div class="input-group">
    <label>Custom minutes</label>
    <input id="custom-min" type="number" placeholder="e.g. 45" min="1" max="1440">
    <div class="btn-group" style="margin-top:8px">
      <button class="btn btn-orange" onclick="sendCmd('add_minutes',+document.getElementById('custom-min').value)">Add time</button>
      <button class="btn btn-orange" onclick="sendCmd('set_day_limit',+document.getElementById('custom-min').value)">Set day limit</button>
    </div>
  </div>
  <div class="btn-group" style="margin-top:10px">
    <button class="btn btn-red" onclick="sendCmd('reset_play_time',0)">Reset play time</button>
    <button class="btn btn-red" onclick="sendCmd('set_day_limit',0)">Remove day limit</button>
  </div>
</div>

<div class="card">
  <h1>Activity log</h1>
  <div id="log" class="log"></div>
</div>

<script>
var ADMIN_KEY = '__ADMIN_KEY_PLACEHOLDER__';
function $(id){return document.getElementById(id)}
function showToast(msg,ok){
  var t=$('toast');t.textContent=msg;t.className='toast '+(ok?'toast-ok':'toast-err')+' show';
  setTimeout(function(){t.className='toast'},2000);
}
function addLog(msg){
  var d=new Date();var ts=d.toLocaleTimeString();
  var el=$('log');el.innerHTML='<div class="log-entry">['+ts+'] '+msg+'</div>'+el.innerHTML;
}
async function sendCmd(action,value){
  if(!value||value<=0){showToast('Invalid value',false);return}
  try{
    var r=await fetch('/admin/command',{
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':'Bearer '+ADMIN_KEY},
      body:JSON.stringify({action:action,value:value})
    });
    var d=await r.json();
    if(r.ok){showToast('Command queued: '+d.cmd_id,true);addLog('Sent: '+action+'='+value+' ('+d.cmd_id+')')}
    else{showToast('Error: '+(d.detail||r.status),false);addLog('Failed: '+action+'='+value)}
  }catch(e){showToast('Network error',false);addLog('Network error')}
}
async function refreshStatus(){
  try{
    var r=await fetch('/admin/status',{headers:{'Authorization':'Bearer '+ADMIN_KEY}});
    var d=await r.json();
    if(r.ok){
      var ls=d.switch_last_seen;
      if(ls&&ls.time){
        $('sw-status').textContent='Online';$('sw-status').className='status-value online';
        $('sw-time').textContent=ls.time.replace('T',' ').substring(0,19);
      }else{$('sw-status').textContent='Offline';$('sw-status').className='status-value offline';$('sw-time').textContent='--'}
      $('sw-pending').textContent=d.pending_count;
    }
  }catch(e){}
}
refreshStatus();setInterval(refreshStatus,10000);
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    key = request.query_params.get("key", "")

    # Determine client IP (check proxy headers first)
    client_ip = request.headers.get("x-real-ip") or \
                request.headers.get("x-forwarded-for", "").split(",")[0].strip() or \
                request.client.host if request.client else ""

    # LAN access → no key required, go straight in
    if _is_lan_ip(client_ip):
        html = DASHBOARD_HTML.replace("__ADMIN_KEY_PLACEHOLDER__", PSK_ADMIN)
        return html

    # External access → must have correct key, otherwise 403
    if key != PSK_ADMIN:
        return HTMLResponse(content=FORBIDDEN_HTML, status_code=403)

    # Correct key → serve dashboard with token embedded
    html = DASHBOARD_HTML.replace("__ADMIN_KEY_PLACEHOLDER__", PSK_ADMIN)
    return html


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
