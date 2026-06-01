#ifndef HEARTBEAT_CLIENT_H
#define HEARTBEAT_CLIENT_H

#include <switch.h>

// 用户常量 — 请在编译前修改这些值
#define TUNNEL_SERVER_HOST  "your-fixed-ip-or-domain"  // 改成你自己的固定IP或域名
#define TUNNEL_SERVER_PORT  9090                        // 服务端监听端口
#define TUNNEL_HEARTBEAT_PATH  "/heartbeat"             // 心跳 API 路径
#define TUNNEL_PSK  "sw-change-me-to-a-long-random-string"  // Switch 端 Token，需和服务端 PSK_SWITCH 一致
#define TUNNEL_INTERVAL_SEC  30                         // 心跳间隔（秒）
#define TUNNEL_CONNECT_TIMEOUT_SEC  10                  // 连接超时
#define TUNNEL_RECV_TIMEOUT_SEC  5                      // 接收超时

// 命令类型
typedef enum {
    TUNNEL_CMD_NONE = 0,
    TUNNEL_CMD_ADD_MINUTES,       // 增加游玩时间（param=分钟数量）
    TUNNEL_CMD_SET_DAY_LIMIT,     // 设置当日时间限额（param=分钟数，0=无限制）
    TUNNEL_CMD_RESET_PLAY_TIME,   // 重置当日游玩时间
    TUNNEL_CMD_SET_WEEKLY_LIMITS, // 设置一周7天限额（weekly[7]数组）
} TunnelCmdType;

// 命令结构
typedef struct {
    TunnelCmdType type;
    int param;                    // 命令参数（分钟数等）
    int day_of_week;              // 指定星期几（0=Sun..6=Sat，-1=未指定）
    int weekly[7];                // 7天限额（Sun=0..Sat=6，-1=未设置）
} TunnelCommand;

// Switch 状态数据（主循环写入，心跳线程读取）
typedef struct {
    int today_limit;              // 今日限额（分钟），-1=未知
    int today_played;             // 今日已玩（分钟），-1=未知
    int today_remaining;          // 今日剩余（分钟），-1=未知
    int weekly_limits[7];         // 一周7天限额（Sun=0..Sat=6），-1=未知
} TunnelStatus;

// 命令队列（线程安全，心跳线程写，主循环读）
#define TUNNEL_CMD_QUEUE_SIZE 8

// 公共 API
void tunnel_start(void);         // 启动心跳线程（net_init 成功后调用）
void tunnel_stop(void);          // 停止心跳线程
bool tunnel_is_running(void);    // 查询状态
int tunnel_dequeue_cmd(TunnelCommand *cmd);  // 从队列取一个命令，返回剩余命令数（0=空）
void tunnel_notify_wake(void);   // 通知心跳线程发生了 sleep/wake，需要重连
void tunnel_update_status(const TunnelStatus *status);  // 主循环调用，更新状态数据

#endif
