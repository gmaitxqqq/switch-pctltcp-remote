// heartbeat_client.c — Switch 远程心跳客户端实现
// 基于 v1.6 恢复（远程连接正常），只加日志节流 + pctl 互斥锁
// 日志：仅异常时打，正常心跳静默，去掉5分钟摘要和线程启停日志

#include "heartbeat_client.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/*  Logging — 委托给 main.c 的 log_msg                                */
/* ------------------------------------------------------------------ */
extern void log_msg(const char *msg);

/* ------------------------------------------------------------------ */
/*  版本号                                                             */
/* ------------------------------------------------------------------ */
#define TUNNEL_VERSION  "1.7.0"

/* ------------------------------------------------------------------ */
/*  前向声明                                                           */
/* ------------------------------------------------------------------ */
static const char *json_find_value(const char *json, const char *key);
static bool json_read_string(const char *value, char *buf, size_t bufsize);
static bool json_read_int(const char *value, int *out);

/* ------------------------------------------------------------------ */
/*  运行时配置                                                           */
/* ------------------------------------------------------------------ */
#define CFG_HOST_MAX    128
#define CFG_PSK_MAX     256

static char s_cfg_host[CFG_HOST_MAX] = "";
static int  s_cfg_port = 0;
static char s_cfg_psk[CFG_PSK_MAX] = "";
static int  s_cfg_interval = 0;
static int  s_cfg_connect_timeout = 0;
static int  s_cfg_recv_timeout = 0;
static bool s_cfg_loaded = false;

static void load_config(void) {
    s_cfg_loaded = false;

    FILE *f = fopen(TUNNEL_CONFIG_PATH, "r");
    if (!f) {
        return;  /* 静默失败，tunnel_start 会检查 s_cfg_loaded */
    }

    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) {
        return;
    }
    buf[n] = '\0';

    const char *val;

    val = json_find_value(buf, "host");
    if (!val || !json_read_string(val, s_cfg_host, sizeof(s_cfg_host))) {
        return;
    }

    val = json_find_value(buf, "port");
    if (!val || !json_read_int(val, &s_cfg_port) || s_cfg_port <= 0 || s_cfg_port > 65535) {
        return;
    }

    val = json_find_value(buf, "psk");
    if (!val || !json_read_string(val, s_cfg_psk, sizeof(s_cfg_psk))) {
        return;
    }

    s_cfg_interval = TUNNEL_DEFAULT_INTERVAL_SEC;
    val = json_find_value(buf, "interval");
    if (val) json_read_int(val, &s_cfg_interval);
    if (s_cfg_interval < 2) s_cfg_interval = TUNNEL_DEFAULT_INTERVAL_SEC;

    s_cfg_connect_timeout = TUNNEL_DEFAULT_CONNECT_TIMEOUT_SEC;
    val = json_find_value(buf, "connect_timeout");
    if (val) json_read_int(val, &s_cfg_connect_timeout);
    if (s_cfg_connect_timeout < 3) s_cfg_connect_timeout = TUNNEL_DEFAULT_CONNECT_TIMEOUT_SEC;

    s_cfg_recv_timeout = TUNNEL_DEFAULT_RECV_TIMEOUT_SEC;
    val = json_find_value(buf, "recv_timeout");
    if (val) json_read_int(val, &s_cfg_recv_timeout);
    if (s_cfg_recv_timeout < 22) s_cfg_recv_timeout = TUNNEL_DEFAULT_RECV_TIMEOUT_SEC;

    s_cfg_loaded = true;
}

/* ------------------------------------------------------------------ */
/*  命令队列（线程安全，环形缓冲区）                                       */
/* ------------------------------------------------------------------ */
static TunnelCommand s_cmd_queue[TUNNEL_CMD_QUEUE_SIZE];
static int s_cmd_head = 0;
static int s_cmd_tail = 0;
static Mutex s_cmd_mutex;

static int cmd_queue_count_locked(void) {
    int count = s_cmd_tail - s_cmd_head;
    if (count < 0) count += TUNNEL_CMD_QUEUE_SIZE;
    return count;
}

static bool cmd_queue_push(const TunnelCommand *cmd) {
    if (!cmd) return false;
    mutexLock(&s_cmd_mutex);

    int next = (s_cmd_tail + 1) % TUNNEL_CMD_QUEUE_SIZE;
    if (next == s_cmd_head) {
        s_cmd_head = (s_cmd_head + 1) % TUNNEL_CMD_QUEUE_SIZE;
        /* 队列满，静默丢弃最旧的，不打日志 */
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
static Mutex s_status_mutex;

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
/*  pctl 互斥锁 — 防止多线程同时调用 pctl_init/exit 导致 IPC 冲突        */
/* ------------------------------------------------------------------ */
static Mutex s_pctl_mutex;

void tunnel_pctl_lock(void) {
    mutexLock(&s_pctl_mutex);
}

void tunnel_pctl_unlock(void) {
    mutexUnlock(&s_pctl_mutex);
}

/* ------------------------------------------------------------------ */
/*  最小 JSON 解析器                                                   */
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

static int json_read_int_array(const char *value, int *arr, int max_count) {
    if (!value || *value != '[' || !arr || max_count <= 0) return 0;
    value++;
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
        const char *dow_val = json_find_value(cmd_val, "day_of_week");
        if (dow_val) json_read_int(dow_val, &cmd.day_of_week);
    } else if (strcmp(action, "reset_play_time") == 0) {
        cmd.type = TUNNEL_CMD_RESET_PLAY_TIME;
    } else if (strcmp(action, "set_weekly_limits") == 0) {
        cmd.type = TUNNEL_CMD_SET_WEEKLY_LIMITS;
        const char *weekly_val = json_find_value(cmd_val, "weekly");
        if (weekly_val) {
            json_read_int_array(weekly_val, cmd.weekly, 7);
        }
    } else {
        return;  /* 未知命令，静默忽略 */
    }

    cmd_queue_push(&cmd);
}

/* ------------------------------------------------------------------ */
/*  HTTP/1.1 客户端（raw socket，无外部依赖）                        */
/*  完全照搬 v1.6 的实现，确保远程连接正常                            */
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
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = connect_timeout;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        int err = errno;
        if (err != 110 && err != 115) {
            char buf[128];
            snprintf(buf, sizeof(buf), "tunnel: connect failed (errno=%d)", err);
            log_msg(buf);
        }
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);

    /* 设置接收超时（长轮询需要 25 秒） */
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

    char req_header[768];
    char full_path[256];
    snprintf(full_path, sizeof(full_path), "%s?key=%s", path, auth_token);
    int body_len = (int)strlen(body);
    snprintf(req_header, sizeof(req_header),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Authorization: Bearer %s\r\n"
        "Content-Length: %d\r\n"
        "User-Agent: Switch-PctlTunnel/" TUNNEL_VERSION "\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n"
        "\r\n",
        full_path, host, port, auth_token, body_len);

    ssize_t sent = send(fd, req_header, strlen(req_header), 0);
    if (sent < 0) {
        close(fd);
        return false;
    }

    sent = send(fd, body, body_len, 0);
    if (sent < 0) {
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
        return false;
    }

    /* 找到 JSON 正文（跳过 HTTP 头部） */
    char *json_start = strstr(resp_buf, "\r\n\r\n");
    if (!json_start) {
        return false;
    }

    json_start += 4;
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

/* 退避参数 — 正常间隔 3 秒（长轮询模式下等待由服务器端处理）
 * 失败时指数退避，最大 300 秒 */
#define BACKOFF_BASE_SEC    3
#define BACKOFF_MAX_SEC     300

static void heartbeat_thread_func(void *arg) {
    (void)arg;
    s_start_time = time(NULL);

    char resp_buf[2048];
    char body_buf[1024];

    int backoff = BACKOFF_BASE_SEC;
    int fail_streak = 0;

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

        /* 发送心跳 */
        bool ok = http_post_json(s_cfg_host, s_cfg_port,
                                 s_cfg_connect_timeout, s_cfg_recv_timeout,
                                 TUNNEL_HEARTBEAT_PATH, s_cfg_psk,
                                 body_buf, resp_buf, sizeof(resp_buf));

        if (ok) {
            parse_heartbeat_response(resp_buf);
            if (fail_streak > 0) {
                log_msg("tunnel: heartbeat recovered, connection OK");
                fail_streak = 0;
            }
            backoff = BACKOFF_BASE_SEC;
        } else {
            fail_streak++;
            /* 只有连续失败 3 次以上才打日志，避免刷屏 */
            if (fail_streak >= 3) {
                char buf[64];
                snprintf(buf, sizeof(buf), "tunnel: heartbeat failed, retry in %ds", backoff);
                log_msg(buf);
            }
        }

        /* 休眠，支持 wake 唤醒 */
        for (int i = 0; i < backoff && s_running; i++) {
            if (s_wake_flag) {
                s_wake_flag = false;
                break;
            }
            svcSleepThread(1000000000ULL);
        }

        /* 退避递增 */
        if (!ok) {
            backoff = backoff * 2;
            if (backoff > BACKOFF_MAX_SEC) backoff = BACKOFF_MAX_SEC;

            /* 重连前重新加载配置文件（支持热重载）*/
            if (fail_streak % 3 == 0) {
                load_config();
                if (!s_cfg_loaded) {
                    break;  /* 配置丢失，退出线程 */
                }
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  公共 API                                                           */
/* ------------------------------------------------------------------ */

void tunnel_init(void) {
    mutexInit(&s_cmd_mutex);
    mutexInit(&s_status_mutex);
    mutexInit(&s_pctl_mutex);
}

void tunnel_start(void) {
    if (s_running) return;

    load_config();
    if (!s_cfg_loaded) {
        return;
    }

    TunnelStatus init_status;
    memset(&init_status, -1, sizeof(init_status));
    tunnel_update_status(&init_status);

    s_running = true;
    Result rc = threadCreate(&s_thread, heartbeat_thread_func, NULL, NULL, 0x10000, 0x2C, -2);
    if (R_FAILED(rc)) {
        s_running = false;
        return;
    }
    rc = threadStart(&s_thread);
    if (R_FAILED(rc)) {
        s_running = false;
        return;
    }
}

void tunnel_stop(void) {
    if (!s_running) return;
    s_running = false;
    s_wake_flag = true;
    threadWaitForExit(&s_thread);
    threadClose(&s_thread);
}

void tunnel_restart(void) {
    if (s_running) {
        tunnel_stop();
        svcSleepThread(1000000000ULL);
    }
    tunnel_start();
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
