"""
switch-pctltcp-remote — Server-side API

Lightweight FastAPI service for Switch remote parental control.
Receives heartbeat from Switch, queues commands for delivery.

Endpoints:
  GET  /                  — Admin web dashboard (browser UI)
  POST /heartbeat         — Switch heartbeat (PSK_SWITCH auth)
  POST /admin/command     — Admin push command (PSK_ADMIN auth)
  GET  /admin/status      — Admin check status (PSK_ADMIN auth)

Security:
  - Dual Bearer token authentication
  - Path whitelist enforced by 雷池 WAF
  - Rate limiting recommended at WAF level
"""

from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from collections import deque
from datetime import datetime
import os

app = FastAPI(title="Switch Parental Control Remote API", version="1.1.0")

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
# Admin web dashboard (single-page, self-contained)
# ---------------------------------------------------------------------------
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
.token-input{width:100%;padding:10px;border:1px solid #d9d9d9;
  border-radius:6px;font-size:14px;font-family:monospace;margin-bottom:12px}
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
    <label>Custom minutes to add</label>
    <input id="custom-min" type="number" placeholder="e.g. 45" min="1" max="1440">
    <div class="btn-group" style="margin-top:8px">
      <button class="btn btn-orange" onclick="sendCmd('add_minutes',+document.getElementById('custom-min').value)">Add custom</button>
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

<div class="card">
  <h1>Settings</h1>
  <p class="subtitle">Admin token (saved in browser)</p>
  <input id="token" class="token-input" placeholder="Paste your admin token here">
  <button class="btn btn-blue" style="width:100%" onclick="saveToken()">Save token</button>
</div>

<script>
const API = '';
let adminToken = localStorage.getItem('switch_admin_token') || '';

function $(id){return document.getElementById(id)}
function showToast(msg,ok){
  const t=$('toast');t.textContent=msg;t.className='toast '+(ok?'toast-ok':'toast-err')+' show';
  setTimeout(()=>t.className='toast',2000);
}
function addLog(msg){
  const d=new Date();const ts=d.toLocaleTimeString();
  const el=$('log');el.innerHTML='<div class="log-entry">['+ts+'] '+msg+'</div>'+el.innerHTML;
}
function saveToken(){
  adminToken=$('token').value.trim();
  localStorage.setItem('switch_admin_token',adminToken);
  showToast('Token saved',true);addLog('Token updated');
}
async function sendCmd(action,value){
  if(!adminToken){showToast('Please set admin token first',false);return}
  if(!value||value<=0){showToast('Invalid value',false);return}
  try{
    const r=await fetch(API+'/admin/command',{
      method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+adminToken},
      body:JSON.stringify({action,value:value})
    });
    const d=await r.json();
    if(r.ok){showToast('Command queued: '+d.cmd_id,true);addLog('Sent: '+action+'='+value+' ('+d.cmd_id+')')}
    else{showToast('Error: '+(d.detail||r.status),false);addLog('Failed: '+action+'='+value+' ('+d.detail+')')}
  }catch(e){showToast('Network error',false);addLog('Network error: '+e.message)}
}
async function refreshStatus(){
  if(!adminToken)return;
  try{
    const r=await fetch(API+'/admin/status',{headers:{'Authorization':'Bearer '+adminToken}});
    const d=await r.json();
    if(r.ok){
      const ls=d.switch_last_seen;
      if(ls&&ls.time){
        $('sw-status').textContent='Online';$('sw-status').className='status-value online';
        $('sw-time').textContent=ls.time.replace('T',' ').substring(0,19);
      }else{$('sw-status').textContent='Offline';$('sw-status').className='status-value offline';$('sw-time').textContent='--'}
      $('sw-pending').textContent=d.pending_count;
    }
  }catch(e){}
}
$('token').value=adminToken;
refreshStatus();setInterval(refreshStatus,10000);
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML


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
