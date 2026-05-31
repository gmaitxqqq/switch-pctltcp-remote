#ifndef HEARTBEAT_CLIENT_H
#define HEARTBEAT_CLIENT_H

#include <switch.h>

// 配置常量 — 用户部署时修改这些
#define TUNNEL_SERVER_HOST  "your-fixed-ip-or-domain"  // 用户改成自己的固定IP或域名
#define TUNNEL_SERVER_PORT  9090                        // 服务端监听端口
#define TUNNEL_HEARTBEAT_PATH  "/heartbeat"             // 心跳 API 路径
#define TUNNEL_PSK  "sw-change-me-to-a-long-random-string"  // Switch 端 Token，必须和服务端 PSK_SWITCH 一致
#define TUNNEL_INTERVAL_SEC  30                         // 心跳间隔（秒）
#define TUNNEL_CONNECT_TIMEOUT_SEC  10                  // 连接超时
#define TUNNEL_RECV_TIMEOUT_SEC  5                      // 接收超时

// 命令类型
typedef enum {
    TUNNEL_CMD_NONE = 0,
    TUNNEL_CMD_ADD_MINUTES,       // 增加游玩时间（param=分钟数）
    TUNNEL_CMD_SET_DAY_LIMIT,     // 设置当日时间限制（param=分钟数，0=无限制）
    TUNNEL_CMD_RESET_PLAY_TIME,   // 重置当日已玩时间
} TunnelCmdType;

// 命令结构
typedef struct {
    TunnelCmdType type;
    int param;                    // 命令参数（分钟数）
} TunnelCommand;

// 命令队列（心跳线程写入，主线程消费）
#define TUNNEL_CMD_QUEUE_SIZE 8

// 公共 API
void tunnel_start(void);         // 启动心跳线程（net_init 成功后调用）
void tunnel_stop(void);          // 停止心跳线程
bool tunnel_is_running(void);    // 查询状态
int tunnel_dequeue_cmd(TunnelCommand *cmd);  // 从队列取出一条命令，返回剩余数量，0=无命令
void tunnel_notify_wake(void);   // 通知心跳线程发生了 sleep/wake，需要重建连接

#endif
