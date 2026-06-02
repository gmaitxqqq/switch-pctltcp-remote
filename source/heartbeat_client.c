// heartbeat_client.c — Switch 远程心跳客户端实现
// V3: 从 SD 卡配置文件读取连接参数（不再硬编码）
//     raw socket HTTP/1.0, Bearer token 认证, 最小 JSON 解析
//     支持上报今日状态/周配额，支持新命令类型
// 心跳线程使用 libnx Thread，命令通过线程安全队列传递给主循环

#include "heartbeat_client.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/*  Logging — 委托给 main.c 的 log_msg                                */
/* ------------------------------------------------------------------ */
extern void log_msg(const char *msg);

/* ------------------------------------------------------------------ */
/*  版本号                                                             */
/* ------------------------------------------------------------------ */
#define TUNNEL_VERSION  "1.6.0"

/* ------------------------------------------------------------------ */
/*  运行时配置（从 SD 卡 tunnel.conf 加载，不再硬编码）                   */
/* ------------------------------------------------------------------ */
#define CFG_HOST_MAX    128
#define CFG_PSK_MAX     256

static char s_cfg_host[CFG_HOST_MAX] = "";       // 服务器地址
static int  s_cfg_port = 0;                       // 服务器端口
static char s_cfg_psk[CFG_PSK_MAX] = "";          // Switch 端 Token
static int  s_cfg_interval = 0;                    // 心跳间隔（秒）
static int  s_cfg_connect_timeout = 0;            // 连接超时
static int  s_cfg_recv_timeout = 0;                // 接收超时
static bool s_cfg_loaded = false;                  // 配置是否已加载

/**
 * 从 SD 卡加载 tunnel.conf 配置文件。
 * 配置文件格式（JSON）:
 * {
 *     "host": "1.2.3.4",
 *     "port": 9090,
 *     "psk": "sw-your-random-string"
 * }
 * 可选字段: "interval", "connect_timeout", "recv_timeout"
 */
static void load_config(void) {
    s_cfg_loaded = false;

    FILE *f = fopen(TUNNEL_CONFIG_PATH, "r");
    if (!f) {
        log_msg("tunnel: config file not found, tunnel disabled");
        log_msg("tunnel: create " TUNNEL_CONFIG_PATH " with host/port/psk");
        return;
    }

    /* 读取文件内容（最大 2KB） */
    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) {
        log_msg("tunnel: config file is empty");
        return;
    }
    buf[n] = '\0';

    /* 解析 JSON — 复用已有的 json_find_value / json_read_string / json_read_int */
    const char *val;

    val = json_find_value(buf, "host");
    if (!val || !json_read_string(val, s_cfg_host, sizeof(s_cfg_host))) {
        log_msg("tunnel: config missing 'host', tunnel disabled");
        return;
    }

    val = json_find_value(buf, "port");
    if (!val || !json_read_int(val, &s_cfg_port) || s_cfg_port <= 0 || s_cfg_port > 65535) {
        log_msg("tunnel: config missing or invalid 'port', tunnel disabled");
        return;
    }

    val = json_find_value(buf, "psk");
    if (!val || !json_read_string(val, s_cfg_psk, sizeof(s_cfg_psk))) {
        log_msg("tunnel: config missing 'psk', tunnel disabled");
        return;
    }

    /* 可选字段 — 缺失则用默认值 */
    s_cfg_interval = TUNNEL_DEFAULT_INTERVAL_SEC;
    val = json_find_value(buf, "interval");
    if (val) json_read_int(val, &s_cfg_interval);
    if (s_cfg_interval < 10) s_cfg_interval = TUNNEL_DEFAULT_INTERVAL_SEC;

    s_cfg_connect_timeout = TUNNEL_DEFAULT_CONNECT_TIMEOUT_SEC;
    val = json_find_value(buf, "connect_timeout");
    if (val) json_read_int(val, &s_cfg_connect_timeout);
    if (s_cfg_connect_timeout < 3) s_cfg_connect_timeout = TUNNEL_DEFAULT_CONNECT_TIMEOUT_SEC;

    s_cfg_recv_timeout = TUNNEL_DEFAULT_RECV_TIMEOUT_SEC;
    val = json_find_value(buf, "recv_timeout");
    if (val) json_read_int(val, &s_cfg_recv_timeout);
    if (s_cfg_recv_timeout < 2) s_cfg_recv_timeout = TUNNEL_DEFAULT_RECV_TIMEOUT_SEC;

    s_cfg_loaded = true;

    char msg[256];
    snprintf(msg, sizeof(msg), "tunnel: config loaded -> %s:%d (interval=%d)",
             s_cfg_host, s_cfg_port, s_cfg_interval);
    log_msg(msg);
}

/* ------------------------------------------------------------------ */
/*  命令队列（线程安全，环形缓冲区）                                       */
/*  使用 libnx Mutex（非 POSIX pthread_mutex）                            */
/* ------------------------------------------------------------------ */
static TunnelCommand s_cmd_queue[TUNNEL_CMD_QUEUE_SIZE];
static int s_cmd_head = 0;
static int s_cmd_tail = 0;
static Mutex s_cmd_mutex;  /* libnx Mutex，无需初始化器 */

/** 队列元素个数（已持有 s_cmd_mutex） */
static int cmd_queue_count_locked(void) {
    int count = s_cmd_tail - s_cmd_head;
    if (count < 0) count += TUNNEL_CMD_QUEUE_SIZE;
    return count;
}

/** 向队列尾压入一个命令，成功返回 true，队列满则丢弃最旧的 */
static bool cmd_queue_push(const TunnelCommand *cmd) {
    if (!cmd) return false;
    mutexLock(&s_cmd_mutex);

    int next = (s_cmd_tail + 1) % TUNNEL_CMD_QUEUE_SIZE;
    if (next == s_cmd_head) {
        /* 队列满，丢弃最旧的腾出空间 */
        s_cmd_head = (s_cmd_head + 1) % TUNNEL_CMD_QUEUE_SIZE;
        log_msg("tunnel: cmd queue overflow, dropped oldest");
    }

    s_cmd_queue[s_cmd_tail] = *cmd;
    s_cmd_tail = next;

    mutexUnlock(&s_cmd_mutex);
    return true;
}

/* ------------------------------------------------------------------ */
/*  状态数据（主循环写，心跳线程读）                                       */
/* ------------------------------------------------------------------ */
static TunnelStatus s_status;
static Mutex s_status_mutex;  /* libnx Mutex */

void tunnel_update_status(const TunnelStatus *status) {
    if (!status) return;
    mutexLock(&s_status_mutex);
    s_status = *status;
    mutexUnlock(&s_status_mutex);
}

static void tunnel_get_status(TunnelStatus *out) {
    if (!out) return;
    mutexLock(&s_status_mutex);
    *out = s_status;
    mutexUnlock(&s_status_mutex);
}

/* ------------------------------------------------------------------ */
/*  最小 JSON 解析器 — 提取 command 对象中的 action / value 等            */
/*  （也供 load_config 使用）                                            */
/* ------------------------------------------------------------------ */

static const char *json_find_value(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(json, pattern);
    if (!pos) return NULL;
    pos += strlen(pattern);
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r' || *pos == ':') {
        pos++;
    }
    return pos;
}

static bool json_read_string(const char *value, char *buf, size_t bufsize) {
    if (!value || *value != '"' || !buf || bufsize == 0) return false;
    value++;
    size_t i = 0;
    while (*value && *value != '"' && i < bufsize - 1) {
        if (*value == '\\' && *(value + 1)) value++;
        buf[i++] = *value++;
    }
    buf[i] = '\0';
    return (*value == '"');
}

static bool json_read_int(const char *value, int *out) {
    if (!value || !out) return false;
    char *end = NULL;
    long val = strtol(value, &end, 10);
    if (end == value) return false;
    *out = (int)val;
    return true;
}

/** 从 JSON 字符串中读取整数数组，最多 max_count 个元素 */
static int json_read_int_array(const char *value, int *arr, int max_count) {
    if (!value || *value != '[' || !arr || max_count <= 0) return 0;
    value++; /* skip '[' */
    int count = 0;
    while (count < max_count) {
        while (*value == ' ' || *value == '\t' || *value == '\n' || *value == '\r') value++;
        if (*value == ']' || *value == '\0') break;
        if (*value == 'n' && strncmp(value, "null", 4) == 0) {
            arr[count] = -1;
            value += 4;
        } else {
            char *end = NULL;
            long val = strtol(value, &end, 10);
            if (end == value) break;
            arr[count] = (int)val;
            value = end;
        }
        count++;
        while (*value == ' ' || *value == '\t') value++;
        if (*value == ',') value++;
    }
    return count;
}

/**
 * 解析心跳响应 JSON，提取命令并推入队列。
 * 响应格式:
 *   {"status":"ok","command":{"action":"add_minutes","value":30,"cmd_id":"cmd-0001"}}
 *   {"status":"ok","command":{"action":"set_weekly_limits","value":0,"weekly":[120,60,...],"cmd_id":"cmd-0002"}}
 *   {"status":"ok","command":{"action":"set_day_limit","value":60,"day_of_week":1,"cmd_id":"cmd-0003"}}
 *   {"status":"ok","command":null}
 */
static void parse_heartbeat_response(const char *response) {
    if (!response) return;

    const char *cmd_val = json_find_value(response, "command");
    if (!cmd_val) return;
    if (strncmp(cmd_val, "null", 4) == 0) return;

    const char *action_val = json_find_value(cmd_val, "action");
    const char *value_val  = json_find_value(cmd_val, "value");

    if (!action_val) return;

    char action[64] = {0};
    if (!json_read_string(action_val, action, sizeof(action))) return;

    int value = 0;
    if (value_val) json_read_int(value_val, &value);

    TunnelCommand cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.param = value;
    cmd.day_of_week = -1;
    memset(cmd.weekly, -1, sizeof(cmd.weekly));

    if (strcmp(action, "add_minutes") == 0) {
        cmd.type = TUNNEL_CMD_ADD_MINUTES;
    } else if (strcmp(action, "set_day_limit") == 0) {
        cmd.type = TUNNEL_CMD_SET_DAY_LIMIT;
        /* 解析可选的 day_of_week */
        const char *dow_val = json_find_value(cmd_val, "day_of_week");
        if (dow_val) json_read_int(dow_val, &cmd.day_of_week);
    } else if (strcmp(action, "reset_play_time") == 0) {
        cmd.type = TUNNEL_CMD_RESET_PLAY_TIME;
    } else if (strcmp(action, "set_weekly_limits") == 0) {
        cmd.type = TUNNEL_CMD_SET_WEEKLY_LIMITS;
        /* 解析 weekly 数组 */
        const char *weekly_val = json_find_value(cmd_val, "weekly");
        if (weekly_val) {
            json_read_int_array(weekly_val, cmd.weekly, 7);
        }
    } else {
        char buf[128];
        snprintf(buf, sizeof(buf), "tunnel: unknown action '%s', ignored", action);
        log_msg(buf);
        return;
    }

    cmd_queue_push(&cmd);

    char buf[128];
    snprintf(buf, sizeof(buf), "tunnel: queued cmd '%s' value=%d dow=%d",
             action, cmd.param, cmd.day_of_week);
    log_msg(buf);
}

/* ------------------------------------------------------------------ */
/*  HTTP/1.0 客户端（raw socket，无外部依赖）                            */
/* ------------------------------------------------------------------ */

static int http_connect(const char *host, int port, int connect_timeout, int recv_timeout) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int gai_rc = getaddrinfo(host, port_str, &hints, &res);
    if (gai_rc != 0 || !res) {
        char buf[128];
        snprintf(buf, sizeof(buf), "tunnel: DNS failed for %s:%d (err=%d)",
                 host, port, gai_rc);
        log_msg(buf);
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        log_msg("tunnel: socket() failed");
        return -1;
    }

    /* 设置连接超时 */
    struct timeval tv;
    tv.tv_sec = connect_timeout;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "tunnel: connect to %s:%d failed (errno=%d)",
                 host, port, errno);
        log_msg(buf);
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);

    /* 设置接收超时 */
    tv.tv_sec = recv_timeout;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return fd;
}

/** 发送 HTTP POST 并读取响应体（只取 JSON 部分） */
static bool http_post_json(const char *host, int port,
                           int connect_timeout, int recv_timeout,
                           const char *path, const char *auth_token,
                           const char *body, char *resp_buf, size_t resp_size) {
    int fd = http_connect(host, port, connect_timeout, recv_timeout);
    if (fd < 0) return false;

    /* 构建 HTTP 请求 */
    char req_header[512];
    int body_len = (int)strlen(body);
    snprintf(req_header, sizeof(req_header),
        "POST %s HTTP/1.0\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Authorization: Bearer %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, port, auth_token, body_len);

    /* 发送请求头 */
    ssize_t sent = send(fd, req_header, strlen(req_header), 0);
    if (sent < 0) {
        log_msg("tunnel: send header failed");
        close(fd);
        return false;
    }

    /* 发送请求体 */
    sent = send(fd, body, body_len, 0);
    if (sent < 0) {
        log_msg("tunnel: send body failed");
        close(fd);
        return false;
    }

    /* 读取响应 */
    ssize_t total = 0;
    while (total < (ssize_t)(resp_size - 1)) {
        ssize_t n = recv(fd, resp_buf + total, resp_size - 1 - total, 0);
        if (n <= 0) break;
        total += n;
    }
    resp_buf[total] = '\0';
    close(fd);

    if (total == 0) {
        log_msg("tunnel: empty response");
        return false;
    }

    /* 找到 JSON 正文（跳过 HTTP 头部） */
    char *json_start = strstr(resp_buf, "\r\n\r\n");
    if (!json_start) {
        log_msg("tunnel: malformed HTTP response");
        return false;
    }
    json_start += 4;

    /* 把 JSON 移到缓冲区开头 */
    size_t json_len = strlen(json_start);
    memmove(resp_buf, json_start, json_len + 1);

    return true;
}

/* ------------------------------------------------------------------ */
/*  心跳线程                                                            */
/* ------------------------------------------------------------------ */
static Thread s_thread;
static volatile bool s_running = false;
static volatile bool s_wake_flag = false;
static time_t s_start_time = 0;

/* 指数退避参数 */
#define BACKOFF_BASE_SEC    30
#define BACKOFF_MAX_SEC     300

static void heartbeat_thread_func(void *arg) {
    (void)arg;
    s_start_time = time(NULL);
    int backoff = BACKOFF_BASE_SEC;

    char resp_buf[2048];
    char body_buf[1024];

    log_msg("tunnel: heartbeat thread started");

    while (s_running) {
        /* 构建心跳 JSON 体 */
        TunnelStatus cur;
        tunnel_get_status(&cur);

        int pos = snprintf(body_buf, sizeof(body_buf),
            "{\"uptime\":%d,\"version\":\"%s\"",
            (int)(time(NULL) - s_start_time), TUNNEL_VERSION);

        if (cur.today_limit >= 0) {
            pos += snprintf(body_buf + pos, sizeof(body_buf) - pos,
                ",\"today_limit\":%d", cur.today_limit);
        }
        if (cur.today_played >= 0) {
            pos += snprintf(body_buf + pos, sizeof(body_buf) - pos,
                ",\"today_played\":%d", cur.today_played);
        }
        if (cur.today_remaining >= 0) {
            pos += snprintf(body_buf + pos, sizeof(body_buf) - pos,
                ",\"today_remaining\":%d", cur.today_remaining);
        }

        /* 检查是否有周配额数据 */
        bool has_weekly = false;
        for (int d = 0; d < 7; d++) {
            if (cur.weekly_limits[d] >= 0) { has_weekly = true; break; }
        }
        if (has_weekly) {
            pos += snprintf(body_buf + pos, sizeof(body_buf) - pos, ",\"weekly_limits\":[");
            for (int d = 0; d < 7; d++) {
                if (d > 0) pos += snprintf(body_buf + pos, sizeof(body_buf) - pos, ",");
                if (cur.weekly_limits[d] >= 0) {
                    pos += snprintf(body_buf + pos, sizeof(body_buf) - pos, "%d", cur.weekly_limits[d]);
                } else {
                    pos += snprintf(body_buf + pos, sizeof(body_buf) - pos, "null");
                }
            }
            pos += snprintf(body_buf + pos, sizeof(body_buf) - pos, "]");
        }

        snprintf(body_buf + pos, sizeof(body_buf) - pos, "}");

        /* 发送心跳（使用运行时配置） */
        bool ok = http_post_json(s_cfg_host, s_cfg_port,
                                 s_cfg_connect_timeout, s_cfg_recv_timeout,
                                 TUNNEL_HEARTBEAT_PATH, s_cfg_psk,
                                 body_buf, resp_buf, sizeof(resp_buf));

        if (ok) {
            parse_heartbeat_response(resp_buf);
            backoff = BACKOFF_BASE_SEC; /* 成功则重置退避 */
        } else {
            /* 失败退避 */
            char buf[64];
            snprintf(buf, sizeof(buf), "tunnel: heartbeat failed, retry in %ds", backoff);
            log_msg(buf);
        }

        /* 休眠，支持 wake 唤醒 */
        for (int i = 0; i < backoff && s_running; i++) {
            if (s_wake_flag) {
                s_wake_flag = false;
                log_msg("tunnel: wake signal received, immediate heartbeat");
                break;
            }
            svcSleepThread(1000000000ULL); /* 1 秒 */
        }

        /* 退避递增 */
        if (!ok) {
            backoff = backoff * 2;
            if (backoff > BACKOFF_MAX_SEC) backoff = BACKOFF_MAX_SEC;
        }
    }

    log_msg("tunnel: heartbeat thread exiting");
}

/* ------------------------------------------------------------------ */
/*  公共 API                                                           */
/* ------------------------------------------------------------------ */

void tunnel_start(void) {
    if (s_running) return;

    /* 先加载配置文件 */
    load_config();
    if (!s_cfg_loaded) {
        log_msg("tunnel: no valid config, tunnel not started");
        return;
    }

    /* 初始化状态 */
    TunnelStatus init_status;
    memset(&init_status, -1, sizeof(init_status));
    tunnel_update_status(&init_status);

    s_running = true;
    Result rc = threadCreate(&s_thread, heartbeat_thread_func, NULL, NULL, 0x2000, 0x2C, -2);
    if (R_FAILED(rc)) {
        char buf[64];
        snprintf(buf, sizeof(buf), "tunnel: threadCreate FAILED (0x%08X)", (unsigned)rc);
        log_msg(buf);
        s_running = false;
        return;
    }
    rc = threadStart(&s_thread);
    if (R_FAILED(rc)) {
        char buf[64];
        snprintf(buf, sizeof(buf), "tunnel: threadStart FAILED (0x%08X)", (unsigned)rc);
        log_msg(buf);
        s_running = false;
        return;
    }
}

void tunnel_stop(void) {
    if (!s_running) return;
    s_running = false;
    s_wake_flag = true; /* 唤醒休眠中的线程 */
    threadWaitForExit(&s_thread);
    threadClose(&s_thread);
}

bool tunnel_is_running(void) {
    return s_running;
}

int tunnel_dequeue_cmd(TunnelCommand *cmd) {
    if (!cmd) return 0;
    memset(cmd, 0, sizeof(*cmd));
    cmd->type = TUNNEL_CMD_NONE;
    cmd->day_of_week = -1;
    memset(cmd->weekly, -1, sizeof(cmd->weekly));

    mutexLock(&s_cmd_mutex);
    if (s_cmd_head == s_cmd_tail) {
        mutexUnlock(&s_cmd_mutex);
        return 0;
    }
    *cmd = s_cmd_queue[s_cmd_head];
    s_cmd_head = (s_cmd_head + 1) % TUNNEL_CMD_QUEUE_SIZE;
    int count = cmd_queue_count_locked();
    mutexUnlock(&s_cmd_mutex);

    return count;
}

void tunnel_notify_wake(void) {
    s_wake_flag = true;
}
