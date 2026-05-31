# switch-pctltcp-remote

Nintendo Switch 家长控制 sysmodule，支持 **局域网 + 远程** 双模式控制。

## 功能

| 模式 | 方式 | 使用场景 |
|------|------|----------|
| **局域网控制** | 浏览器访问 `http://<Switch-IP>:8081` | 家里同一个 WiFi |
| **远程控制** | 通过固定 IP 服务器下发命令 | 外出时远程管理 |

### 特性
- 开机自启（boot2 sysmodule）
- Web UI 直观操作
- 按天设置游玩时间限制
- 实时查看剩余/已玩时间
- 远程心跳隧道（主动外连，无需端口映射）
- 双 Token 认证（Switch 端 + 管理员端分离）
- 休眠/唤醒自动恢复
- 网络断线自动重连

## 快速开始

### Switch 端

#### 前置要求
- Nintendo Switch (Atmosphere 22.1.0+)
- devkitPro + libnx 开发环境

#### 编译
```bash
export DEVKITPRO=/path/to/devkitpro
make
```

#### 安装
将生成的 `pctltcp-sysmodule.nsp` 复制到：
```
sdmc:/atmosphere/contents/010000000000BD23/exefs.nsp
```

创建启动标记：
```
sdmc:/atmosphere/contents/010000000000BD23/flags/boot2.flag
```

#### 配置远程连接

编辑 `source/heartbeat_client.h`，修改以下常量：

```c
#define TUNNEL_SERVER_HOST  "你的固定IP或域名"
#define TUNNEL_SERVER_PORT  9090
#define TUNNEL_PSK  "sw-你生成的随机字符串"
```

> ⚠️ `TUNNEL_PSK` 必须与服务端 `docker-compose.yml` 中的 `PSK_SWITCH` 一致！

然后重新编译安装。

### 服务端

#### 前置要求
- Docker + Docker Compose
- 雷池 WAF（推荐，提供 TLS 和防护）

#### 部署

1. 进入 `server/` 目录

2. **修改 Token**（编辑 `docker-compose.yml`）：
   ```yaml
   - PSK_SWITCH=sw-你生成的随机字符串      # 必须与 Switch 端 TUNNEL_PSK 一致
   - PSK_ADMIN=adm-另一个不同的随机字符串   # 你自己管理用的 token
   ```

3. 启动服务：
   ```bash
   docker compose up -d
   ```

4. 验证服务：
   ```bash
   # 模拟 Switch 心跳
   curl -X POST http://127.0.0.1:8888/heartbeat \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer sw-你的PSK_SWITCH" \
     -d '{"uptime": 0}'

   # 下发命令（给 Switch 增加 30 分钟）
   curl -X POST http://127.0.0.1:8888/admin/command \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer adm-你的PSK_ADMIN" \
     -d '{"action": "add_minutes", "value": 30}'
   ```

#### 雷池 WAF 配置

在雷池中新建防护站点：
- **后端地址**: `http://127.0.0.1:8888`
- **域名/端口**: 按你的域名或 IP 配置

推荐添加的自定义规则：
| 规则 | 说明 |
|------|------|
| 路径不在 `/heartbeat` `/admin/` `/health` → 拦截 | 只放行这三个 API |
| 请求方法 + 路径不匹配 → 拦截 | `/heartbeat` 只允许 POST |
| `Authorization` header 缺失 → 拦截 | 没带 token 直接拒绝 |
| 请求频率超限 → 拦截 | 防暴力请求 |

## 使用方式

### 局域网控制（不变）

浏览器打开 `http://<Switch-IP>:8081`，使用 Web UI 操作。

### 远程控制

使用 curl 或任意 HTTP 客户端：

```bash
# 查看 Switch 在线状态
curl https://你的域名/admin/status \
  -H "Authorization: Bearer adm-你的PSK_ADMIN"

# 增加游玩时间 60 分钟
curl -X POST https://你的域名/admin/command \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer adm-你的PSK_ADMIN" \
  -d '{"action": "add_minutes", "value": 60}'

# 设置当日时间限制 120 分钟
curl -X POST https://你的域名/admin/command \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer adm-你的PSK_ADMIN" \
  -d '{"action": "set_day_limit", "value": 120}'

# 重置已玩时间
curl -X POST https://你的域名/admin/command \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer adm-你的PSK_ADMIN" \
  -d '{"action": "reset_play_time", "value": 0}'
```

## 架构

```
┌─────────────┐         ┌──────────────────────┐         ┌─────────────┐
│   Switch    │  心跳   │  固定IP服务器         │  管理API │  你的设备    │
│  sysmodule  │ ──────> │  Docker + FastAPI    │ <────── │  浏览器/curl │
│  :8081 LAN  │ <────── │  雷池 WAF (TLS)      │ ──────> │             │
│  心跳线程   │  命令   │  :8888 内部           │         │             │
└─────────────┘         └──────────────────────┘         └─────────────┘
```

## 安全说明

- **双 Token 分离**: Switch 用 `PSK_SWITCH`（只能心跳），管理员用 `PSK_ADMIN`（可下发命令）
- **命令队列模式**: 心跳线程不直接调用 pctl IPC，通过队列交给主循环串行执行
- **雷池 WAF**: 网络层防护，TLS 终止，路径白名单，频率限制
- **V1 使用 HTTP + Bearer Token**: 安全性由 Token + WAF 保证，V2 可增加 TLS 客户端

## 文件结构

```
├── source/
│   ├── main.c                 # 主程序入口 + 心跳集成
│   ├── http_server.c/h        # 局域网 HTTP 服务端（保留原样）
│   ├── pctl_handler.c/h       # pctl IPC 封装（保留原样）
│   └── heartbeat_client.c/h   # 远程心跳客户端（新增）
├── server/
│   ├── app.py                 # FastAPI 服务端
│   ├── requirements.txt
│   ├── Dockerfile
│   └── docker-compose.yml
├── Makefile
├── pctltcp-sysmodule.json     # NPDM 权限配置
├── toolbox.json               # Hekate 工具箱声明
└── README.md
```

## 版本历史

- **v1.5.0** - 新增远程心跳隧道，支持外网控制
- **v1.4.1** - 修复 sleep/wake 检测
- **v1.4** - 健康检查 + 网络恢复
- **v1.3** - 初始版本，局域网 HTTP 控制
