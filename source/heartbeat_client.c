// heartbeat_client.c — Switch 端心跳客户端核心实现
// V1: raw socket HTTP/1.0, Bearer token 认证, 极简 JSON 解析
// 心跳线程使用 libnx Thread, 命令通过线程安全队列传递给主循环

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
/*  命令队列（线程安全环形缓冲区）                                       */
/* ------------------------------------------------------------------ */
static TunnelCommand s_cmd_queue[TUNNEL_CMD_QUEUE_SIZE];
static int s_cmd_head = 0;
static int s_cmd_tail = 0;
static pthread_mutex_t s_cmd_mutex = PTHREAD_MUTEX_INITIALIZER;

/** 队列内元素数量（调用者需已持有 s_cmd_mutex） */
static int cmd_queue_count_locked(void) {
    int count = s_cmd_tail - s_cmd_head;
    if (count < 0) count += TUNNEL_CMD_QUEUE_SIZE;
    return count;
}

/** 向队列尾部压入一条命令，成功返回 true，队列满返回 false */
static bool cmd_queue_push(const TunnelCommand *cmd) {
    if (!cmd) return false;
    pthread_mutex_lock(&s_cmd_mutex);

    int next = (s_cmd_tail + 1) % TUNNEL_CMD_QUEUE_SIZE;
    if (next == s_cmd_head) {
        /* 队列已满，丢弃最旧的命令腾出空间 */
        s_cmd_head = (s_cmd_head + 1) % TUNNEL_CMD_QUEUE_SIZE;
        log_msg("tunnel: cmd queue overflow, dropped oldest");
    }

    s_cmd_queue[s_cmd_tail] = *cmd;
    s_cmd_tail = next;

    pthread_mutex_unlock(&s_cmd_mutex);
    return true;
}

/* ------------------------------------------------------------------ */
/*  极简 JSON 解析器 — 仅提取 command 对象中的 action / value            */
/* ------------------------------------------------------------------ */

/**
 * 在 json 字符串中查找 key 对应的值起始位置。
 * 找到 "key" 后跳过空白和冒号，返回值指针。
 * 未找到返回 NULL。
 */
static const char *json_find_value(const char *json, const char *key) {
    if (!json || !key) return NULL;

    /* 构造搜索模式: "key" */
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *pos = strstr(json, pattern);
    if (!pos) return NULL;

    pos += strlen(pattern);
    /* 跳过空白和冒号 */
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r' || *pos == ':') {
        pos++;
    }
    return pos;
}

/**
 * 从 value 指针读取 JSON 字符串，写入 buf（最多 bufsize-1 字节）。
 * value 应指向 '"' 开头的字符串值。成功返回 true。
 */
static bool json_read_string(const char *value, char *buf, size_t bufsize) {
    if (!value || *value != '"' || !buf || bufsize == 0) return false;
    value++; /* 跳过开头引号 */

    size_t i = 0;
    while (*value && *value != '"' && i < bufsize - 1) {
        if (*value == '\\' && *(value + 1)) {
            value++; /* 跳过转义字符 */
        }
        buf[i++] = *value++;
    }
    buf[i] = '\0';
    return (*value == '"');
}

/**
 * 从 value 指针读取 JSON 整数值。成功返回 true。
 */
static bool json_read_int(const char *value, int *out) {
    if (!value || !out) return false;
    char *end = NULL;
    long val = strtol(value, &end, 10);
    if (end == value) return false; /* 未消费任何字符 */
    *out = (int)val;
    return true;
}

/**
 * 解析心跳响应 JSON，如果有命令则入队。
 * 期望格式:
 *   {"status":"ok","command":{"action":"add_minutes","value":30,"cmd_id":"abc123"}}
 *   {"status":"ok","command":null}
 */
static void parse_heartbeat_response(const char *response) {
    if (!response) return;

    /* 查找 "command" 的值 */
    const char *cmd_val = json_find_value(response, "command");
    if (!cmd_val) return;

    /* command 为 null → 无待执行命令 */
    if (strncmp(cmd_val, "null", 4) == 0) return;

    /* command 是对象 → 提取 action 和 value */
    const char *action_val = json_find_value(cmd_val, "action");
    const char *value_val  = json_find_value(cmd_val, "value");

    if (!action_val) return;

    char action[64] = {0};
    if (!json_read_string(action_val, action, sizeof(action))) return;

    TunnelCommand cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.param = 0;

    if (strcmp(action, "add_minutes") == 0) {
        cmd.type = TUNNEL_CMD_ADD_MINUTES;
        if (value_val) json_read_int(value_val, &cmd.param);
    } else if (strcmp(action, "set_day_limit") == 0) {
        cmd.type = TUNNEL_CMD_SET_DAY_LIMIT;
        if (value_val) json_read_int(value_val, &cmd.param);
    } else if (strcmp(action, "reset_play_time") == 0) {
        cmd.type = TUNNEL_CMD_RESET_PLAY_TIME;
        cmd.param = 0;
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg), "tunnel: unknown action '%s'", action);
        log_msg(msg);
        return;
    }

    if (cmd_queue_push(&cmd)) {
        char msg[128];
        snprintf(msg, sizeof(msg), "tunnel: enqueued cmd type=%d param=%d", cmd.type, cmd.param);
        log_msg(msg);
    } else {
        log_msg("tunnel: cmd queue push failed (should not happen)");
    }
}

/* ------------------------------------------------------------------ */
/*  Raw Socket HTTP 客户端                                              */
/* ------------------------------------------------------------------ */

/**
 * 带超时的非阻塞 connect。
 * 成功返回 0，超时或失败返回 -1。
 */
static int connect_with_timeout(int sockfd, const struct sockaddr *addr,
                                 socklen_t addrlen, int timeout_sec) {
    /* 设为非阻塞 */
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;

    int ret = connect(sockfd, addr, addrlen);
    if (ret == 0) {
        /* 立即连接成功 */
        fcntl(sockfd, F_SETFL, flags);
        return 0;
    }
    if (errno != EINPROGRESS) {
        fcntl(sockfd, F_SETFL, flags);
        return -1;
    }

    /* 等待连接完成 */
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sockfd, &writefds);
    struct timeval tv;
    tv.tv_sec  = timeout_sec;
    tv.tv_usec = 0;
    ret = select(sockfd + 1, NULL, &writefds, NULL, &tv);

    /* 恢复阻塞模式 */
    fcntl(sockfd, F_SETFL, flags);

    if (ret <= 0) {
        return -1; /* 超时或 select 出错 */
    }

    /* 检查 SO_ERROR 确认连接是否真正成功 */
    int error = 0;
    socklen_t errlen = sizeof(error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &errlen) < 0) {
        return -1;
    }
    if (error != 0) {
        errno = error;
        return -1;
    }
    return 0;
}

/**
 * 执行一次心跳：建立 TCP 连接 → 发送 HTTP POST → 接收响应 → 解析命令。
 * 成功返回 0，失败返回 -1。
 */
static int do_heartbeat(void) {
    /* ---- DNS 解析 ---- */
    struct hostent *he = gethostbyname(TUNNEL_SERVER_HOST);
    if (!he) {
        log_msg("tunnel: DNS resolution failed");
        return -1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port  = htons(TUNNEL_SERVER_PORT);
    memcpy(&sa.sin_addr, he->h_addr_list[0], (size_t)he->h_length);

    /* ---- 创建 socket ---- */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_msg("tunnel: socket() failed");
        return -1;
    }

    /* 设置接收超时 */
    struct timeval recv_tv;
    recv_tv.tv_sec  = TUNNEL_RECV_TIMEOUT_SEC;
    recv_tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &recv_tv, sizeof(recv_tv));

    /* ---- 带超时连接 ---- */
    if (connect_with_timeout(sockfd, (struct sockaddr *)&sa, sizeof(sa),
                             TUNNEL_CONNECT_TIMEOUT_SEC) < 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "tunnel: connect to %s:%d failed/timed out",
                 TUNNEL_SERVER_HOST, TUNNEL_SERVER_PORT);
        log_msg(msg);
        close(sockfd);
        return -1;
    }

    /* ---- 构造 HTTP POST 请求 ---- */
    u64 now = (u64)time(NULL);
    u64 uptime = (now > s_start_time) ? (now - s_start_time) : 0;

    char body[64];
    snprintf(body, sizeof(body), "{\"uptime\":%llu}", (unsigned long long)uptime);

    char request[1024];
    int req_len = snprintf(request, sizeof(request),
        "POST %s HTTP/1.0\r\n"
        "Host: %s:%d\r\n"
        "Authorization: Bearer %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "\r\n"
        "%s",
        TUNNEL_HEARTBEAT_PATH,
        TUNNEL_SERVER_HOST, TUNNEL_SERVER_PORT,
        TUNNEL_PSK,
        (int)strlen(body),
        body);

    if (req_len < 0 || req_len >= (int)sizeof(request)) {
        log_msg("tunnel: request buffer overflow");
        close(sockfd);
        return -1;
    }

    /* ---- 发送请求 ---- */
    int total = req_len;
    int sent  = 0;
    while (sent < total) {
        int n = send(sockfd, request + sent, total - sent, 0);
        if (n <= 0) {
            log_msg("tunnel: send() failed");
            close(sockfd);
            return -1;
        }
        sent += n;
    }

    /* ---- 接收响应 ---- */
    char response[2048];
    int resp_len = 0;
    while (resp_len < (int)sizeof(response) - 1) {
        int n = recv(sockfd, response + resp_len,
                     (int)sizeof(response) - 1 - resp_len, 0);
        if (n <= 0) break;
        resp_len += n;
    }
    response[resp_len] = '\0';
    close(sockfd);

    if (resp_len == 0) {
        log_msg("tunnel: empty response");
        return -1;
    }

    /* ---- 检查 HTTP 状态码 ---- */
    if (strncmp(response, "HTTP/1.", 7) == 0) {
        int status = 0;
        if (sscanf(response, "HTTP/1.%*d %d", &status) == 1 && status != 200) {
            char msg[64];
            snprintf(msg, sizeof(msg), "tunnel: HTTP %d", status);
            log_msg(msg);
            return -1;
        }
    }

    /* ---- 提取 HTTP Body（跳过 \r\n\r\n 头部） ---- */
    char *body_start = strstr(response, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
    } else {
        body_start = strstr(response, "\n\n");
        if (body_start) body_start += 2;
    }

    if (!body_start || *body_start == '\0') {
        log_msg("tunnel: no HTTP body in response");
        return -1;
    }

    /* ---- 解析 JSON 命令 ---- */
    parse_heartbeat_response(body_start);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  心跳线程                                                           */
/* ------------------------------------------------------------------ */
static Thread s_thread;
static volatile bool s_running       = false;
static volatile bool s_wake_notified = false;
static u64 s_start_time = 0;

/**
 * 心跳线程主函数。
 * 循环发送心跳，失败时指数退避（30s→60s→120s→…→最大 300s）。
 * 成功后恢复正常间隔。
 */
static void heartbeat_thread_func(void *arg) {
    (void)arg;

    s_start_time = (u64)time(NULL);
    int backoff_sec = TUNNEL_INTERVAL_SEC;

    {
        char msg[128];
        snprintf(msg, sizeof(msg), "tunnel: thread started (target %s:%d)",
                 TUNNEL_SERVER_HOST, TUNNEL_SERVER_PORT);
        log_msg(msg);
    }

    while (s_running) {
        /* 检查 wake 通知 */
        if (s_wake_notified) {
            s_wake_notified = false;
            backoff_sec = TUNNEL_INTERVAL_SEC;
            log_msg("tunnel: wake notified, resetting backoff");
        }

        /* 发送心跳 */
        int rc = do_heartbeat();
        if (!s_running) break;

        if (rc == 0) {
            /* 成功：恢复正常间隔 */
            backoff_sec = TUNNEL_INTERVAL_SEC;
            /* 间隔等待（每秒检查 s_running 和 s_wake_notified） */
            for (int i = 0; i < TUNNEL_INTERVAL_SEC && s_running && !s_wake_notified; i++) {
                svcSleepThread(1000000000ULL); /* 1 秒 */
            }
        } else {
            /* 失败：按退避时间等待，然后加倍 */
            char msg[128];
            snprintf(msg, sizeof(msg), "tunnel: heartbeat failed, backing off %ds", backoff_sec);
            log_msg(msg);

            for (int i = 0; i < backoff_sec && s_running && !s_wake_notified; i++) {
                svcSleepThread(1000000000ULL);
            }

            backoff_sec *= 2;
            if (backoff_sec > 300) backoff_sec = 300;
        }
    }

    log_msg("tunnel: thread exiting");
}

/* ------------------------------------------------------------------ */
/*  公共 API                                                           */
/* ------------------------------------------------------------------ */

void tunnel_start(void) {
    if (s_running) return;

    s_running       = true;
    s_wake_notified = false;
    s_cmd_head      = 0;
    s_cmd_tail      = 0;

    /* libnx Thread: 8 KiB 栈, 优先级 0x2C, 任意核心 */
    Result rc = threadCreate(&s_thread, heartbeat_thread_func, NULL,
                             NULL, 0x2000, 0x2C, -2);
    if (R_FAILED(rc)) {
        s_running = false;
        char msg[128];
        snprintf(msg, sizeof(msg), "tunnel: threadCreate failed (0x%08X)", (unsigned)rc);
        log_msg(msg);
        return;
    }

    rc = threadStart(&s_thread);
    if (R_FAILED(rc)) {
        s_running = false;
        threadClose(&s_thread);
        char msg[128];
        snprintf(msg, sizeof(msg), "tunnel: threadStart failed (0x%08X)", (unsigned)rc);
        log_msg(msg);
        return;
    }

    log_msg("tunnel: started");
}

void tunnel_stop(void) {
    if (!s_running) return;

    s_running = false;

    /* 等待线程退出 */
    Result rc = threadWaitForExit(&s_thread);
    if (R_FAILED(rc)) {
        char msg[128];
        snprintf(msg, sizeof(msg), "tunnel: threadWaitForExit failed (0x%08X)", (unsigned)rc);
        log_msg(msg);
    }

    rc = threadClose(&s_thread);
    if (R_FAILED(rc)) {
        char msg[128];
        snprintf(msg, sizeof(msg), "tunnel: threadClose failed (0x%08X)", (unsigned)rc);
        log_msg(msg);
    }

    log_msg("tunnel: stopped");
}

bool tunnel_is_running(void) {
    return s_running;
}

int tunnel_dequeue_cmd(TunnelCommand *cmd) {
    if (!cmd) return 0;

    pthread_mutex_lock(&s_cmd_mutex);

    if (s_cmd_head == s_cmd_tail) {
        /* 队列为空 */
        pthread_mutex_unlock(&s_cmd_mutex);
        cmd->type = TUNNEL_CMD_NONE;
        cmd->param = 0;
        return 0;
    }

    *cmd = s_cmd_queue[s_cmd_head];
    s_cmd_head = (s_cmd_head + 1) % TUNNEL_CMD_QUEUE_SIZE;

    int remaining = cmd_queue_count_locked();
    pthread_mutex_unlock(&s_cmd_mutex);

    return remaining;
}

void tunnel_notify_wake(void) {
    s_wake_notified = true;
}
