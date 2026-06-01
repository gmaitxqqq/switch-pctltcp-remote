// main.c — Switch 家长控制 sysmodule 主程序
// V1.6.0 - 远程隧道 + 周配额 + 今日状态上报

#include <switch.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "http_server.h"
#include "pctl_handler.h"
#include "heartbeat_client.h"

/* ------------------------------------------------------------------ */
/*  Logging — 写文件到 SD 卡                                           */
/* ------------------------------------------------------------------ */
#define LOG_PATH  "sdmc:/switch/pctltcp-sysmodule/log.txt"

void log_msg(const char *msg) {
    if (!msg) return;
    FILE *f = fopen(LOG_PATH, "a");
    if (f) {
        Result rc;
        u64 now_posix = 0;
        rc = timeGetCurrentTime(TimeType_NetworkSystemClock, &now_posix);
        if (R_FAILED(rc) || now_posix <= 946684800ULL) {
            rc = timeGetCurrentTime(TimeType_UserSystemClock, &now_posix);
        }
        if (R_SUCCEEDED(rc) && now_posix > 946684800ULL) {
            TimeCalendarTime cal;
            TimeCalendarAdditionalInfo additional;
            rc = timeToCalendarTimeWithMyRule(now_posix, &cal, &additional);
            if (R_FAILED(rc) && s_tz_rule_loaded_from_main) {
                /* fallback — use cached tz rule */
                extern TimeZoneRule s_tz_rule_main;
                rc = timeToCalendarTime(&s_tz_rule_main, now_posix, &cal, &additional);
            }
            if (R_SUCCEEDED(rc)) {
                fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                        cal.year, cal.month, cal.day,
                        cal.hour, cal.minute, cal.second, msg);
                fclose(f);
                return;
            }
        }
        fprintf(f, "[?] %s\n", msg);
        fclose(f);
    }
}

/* Timezone rule cache for log_msg fallback */
static TimeZoneRule s_tz_rule_main;
static bool s_tz_rule_loaded_from_main = false;

static void log_result(const char *ctx, Result rc) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s: %s (0x%08X)",
             ctx, R_SUCCEEDED(rc) ? "OK" : "FAILED", (unsigned)rc);
    log_msg(buf);
}

static void ip_to_str(u32 ip, char *buf, size_t bufsize) {
    snprintf(buf, bufsize, "%d.%d.%d.%d",
             (int)((ip >>  0) & 0xFF),
             (int)((ip >>  8) & 0xFF),
             (int)((ip >> 16) & 0xFF),
             (int)((ip >> 24) & 0xFF));
}

static bool g_net_up = false;

/* ------------------------------------------------------------------ */
/*  更新隧道状态（主循环调用，读取 pctl 数据供心跳上报）                    */
/* ------------------------------------------------------------------ */
static void update_tunnel_status(void) {
    TunnelStatus status;
    memset(&status, -1, sizeof(status));

    Result rc = pctl_init();
    if (R_FAILED(rc)) {
        /* pctl 不可用，跳过 */
        return;
    }

    /* 今日限额 */
    u32 daily_limit = 0;
    if (R_SUCCEEDED(pctl_get_daily_limit_minutes(&daily_limit))) {
        status.today_limit = (int)daily_limit;
    }

    /* 今日剩余时间 */
    u64 remaining_ns = 0;
    if (R_SUCCEEDED(pctl_get_remaining_time(&remaining_ns))) {
        status.today_remaining = NS_TO_MINUTES(remaining_ns);
        /* 已玩 = 限额 - 剩余 */
        if (status.today_limit >= 0 && status.today_remaining >= 0) {
            status.today_played = status.today_limit - status.today_remaining;
            if (status.today_played < 0) status.today_played = 0;
        }
    }

    /* 一周7天限额（Sun=0..Sat=6） */
    for (int d = 0; d < 7; d++) {
        u32 day_limit = 0;
        if (R_SUCCEEDED(pctl_get_day_limit_minutes(d, &day_limit))) {
            status.weekly_limits[d] = (int)day_limit;
        }
    }

    pctl_exit();

    tunnel_update_status(&status);
}

static Result net_init(void) {
    Result rc;
    rc = nifmInitialize(NifmServiceType_System);
    if (R_FAILED(rc)) {
        rc = nifmInitialize(NifmServiceType_User);
    }
    if (R_FAILED(rc)) {
        log_result("nifmInitialize", rc);
        return rc;
    }
    SocketInitConfig cfg = {
        .tcp_tx_buf_size = 0x4000,
        .tcp_rx_buf_size = 0x4000,
        .tcp_tx_buf_max_size = 0x10000,
        .tcp_rx_buf_max_size = 0x10000,
        .udp_tx_buf_size = 0x1000,
        .udp_rx_buf_size = 0x4000,
        .sb_efficiency = 2,
        .bsd_service_type = BsdServiceType_System,
    };
    rc = socketInitialize(&cfg);
    if (R_FAILED(rc)) {
        log_result("socketInitialize", rc);
        nifmExit();
        return rc;
    }
    http_server_start();
    if (!http_server_is_running()) {
        log_msg("HTTP server start FAILED.");
        socketExit();
        nifmExit();
        return -1;
    }
    g_net_up = true;
    log_msg("Network services initialized, HTTP server started.");
    char ip[64] = {0};
    u32 ipaddr = 0;
    if (R_SUCCEEDED(nifmGetCurrentIpAddress(&ipaddr)) && ipaddr != 0) {
        ip_to_str(ipaddr, ip, sizeof(ip));
        char msg[256];
        snprintf(msg, sizeof(msg), "Web UI: http://%s:%d", ip, HTTP_PORT);
        log_msg(msg);
    }

    /* 启动远程隧道 */
    tunnel_start();
    if (tunnel_is_running()) {
        log_msg("Remote tunnel started.");
    } else {
        log_msg("WARNING: Remote tunnel failed to start.");
    }

    return 0;
}

static void net_cleanup(void) {
    tunnel_stop();

    if (http_server_is_running()) {
        http_server_stop();
        log_msg("HTTP server stopped.");
    }
    if (g_net_up) {
        socketExit();
        nifmExit();
        log_msg("Network services cleaned up.");
    }
    g_net_up = false;
}

static Result http_restart(void) {
    http_server_stop();
    log_msg("Waiting for WiFi to reconnect...");
    int wifi_wait = 0;
    while (wifi_wait < 30) {
        u32 ip = 0;
        Result rc = nifmGetCurrentIpAddress(&ip);
        if (R_SUCCEEDED(rc) && ip != 0) {
            char ipstr[64];
            ip_to_str(ip, ipstr, sizeof(ipstr));
            char msg[256];
            snprintf(msg, sizeof(msg), "WiFi back (IP=%s), restarting HTTP server.", ipstr);
            log_msg(msg);
            break;
        }
        svcSleepThread(1000000000ULL);
        wifi_wait++;
    }
    if (wifi_wait >= 30) {
        log_msg("WiFi not back after 30s, restarting HTTP server anyway.");
    }
    svcSleepThread(2000000000ULL);
    http_server_start();
    if (!http_server_is_running()) {
        log_msg("HTTP server restart FAILED.");
        return -1;
    }
    log_msg("HTTP server restarted successfully.");
    return 0;
}

/* ---- 远程命令执行（主线程串行执行，避免 pctl 并发） ---- */

static void execute_tunnel_cmd(TunnelCommand *cmd) {
    if (!cmd || cmd->type == TUNNEL_CMD_NONE) return;

    Result rc = pctl_init();
    if (R_FAILED(rc)) {
        log_result("tunnel: pctl_init", rc);
        return;
    }

    switch (cmd->type) {
    case TUNNEL_CMD_ADD_MINUTES: {
        u32 daily_limit = 0;
        pctl_get_daily_limit_minutes(&daily_limit);
        u32 new_limit = daily_limit + (u32)cmd->param;
        if (new_limit > 1440) new_limit = 1440;
        int today = pctl_get_today_day();
        rc = pctl_set_day_limit_minutes(today, new_limit);
        break;
    }
    case TUNNEL_CMD_SET_DAY_LIMIT: {
        if (cmd->day_of_week >= 0 && cmd->day_of_week <= 6) {
            /* 指定了星期几：设置对应天的限额 */
            rc = pctl_set_day_limit_minutes(cmd->day_of_week, (u32)cmd->param);
        } else {
            /* 未指定星期几：设置今天的限额（旧行为兼容） */
            int today = pctl_get_today_day();
            rc = pctl_set_day_limit_minutes(today, (u32)cmd->param);
        }
        break;
    }
    case TUNNEL_CMD_RESET_PLAY_TIME: {
        rc = pctl_reset_play_time();
        break;
    }
    case TUNNEL_CMD_SET_WEEKLY_LIMITS: {
        /* 设置一周7天限额（Sun=0..Sat=6） */
        int ok_count = 0;
        for (int d = 0; d < 7; d++) {
            if (cmd->weekly[d] >= 0) {
                Result day_rc = pctl_set_day_limit_minutes(d, (u32)cmd->weekly[d]);
                if (R_SUCCEEDED(day_rc)) ok_count++;
            }
        }
        if (ok_count > 0) rc = 0;
        else rc = -1;
        char msg[64];
        snprintf(msg, sizeof(msg), "tunnel: set_weekly_limits %d/7 days ok", ok_count);
        log_msg(msg);
        pctl_exit();
        return;
    }
    default:
        break;
    }

    pctl_exit();

    char msg[128];
    snprintf(msg, sizeof(msg), "tunnel: cmd %d param=%d dow=%d -> %s (0x%08X)",
             cmd->type, cmd->param, cmd->day_of_week,
             R_SUCCEEDED(rc) ? "OK" : "FAIL", (unsigned)rc);
    log_msg(msg);
}

static bool s_base_ready = false;

static Result init_services(void) {
    mkdir("sdmc:/switch", 0777);
    mkdir("sdmc:/switch/pctltcp-sysmodule", 0777);
    log_msg("pctltcp-sysmodule starting (v1.6.0 - weekly limits)...");
    {
        Result tz_rc = pctl_load_timezone();
        if (R_FAILED(tz_rc)) {
            char buf[128];
            snprintf(buf, sizeof(buf), "WARNING: timezone load failed (0x%08X), day-of-week may be wrong", (unsigned)tz_rc);
            log_msg(buf);
        } else {
            log_msg("Timezone rule loaded successfully.");
        }
    }
    {
        u64 test_time = 0;
        Result time_rc = timeGetCurrentTime(TimeType_NetworkSystemClock, &test_time);
        if (R_FAILED(time_rc)) {
            time_rc = timeGetCurrentTime(TimeType_UserSystemClock, &test_time);
        }
        char buf[128];
        snprintf(buf, sizeof(buf), "Time service: %s (time=%llu, rc=0x%08X)",
                 R_SUCCEEDED(time_rc) ? "OK" : "FAILED",
                 (unsigned long long)test_time, (unsigned)time_rc);
        log_msg(buf);
    }
    s_base_ready = true;
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    svcSleepThread(15000000000ULL);  /* 15 seconds */
    Result rc = init_services();
    if (R_FAILED(rc)) {
        log_msg("FATAL: Service initialization failed, entering idle loop.");
    }
    if (s_base_ready) {
        for (int attempt = 0; attempt < 30; attempt++) {
            rc = net_init();
            if (R_SUCCEEDED(rc)) break;
            svcSleepThread(5000000000ULL);
        }
        if (R_FAILED(rc)) {
            log_msg("WARNING: Network init failed after 30 retries");
        }
    }
    log_msg("pctltcp-sysmodule initialization complete.");

    u64 loop = 0;
    char last_ip[64] = {0};
    u64 last_ip_check = 0;
    int nifm_fail_count = 0;

    while (1) {
        u64 t_before = 0;
        timeGetCurrentTime(TimeType_UserSystemClock, &t_before);
        svcSleepThread(1000000000ULL);
        u64 t_after = 0;
        timeGetCurrentTime(TimeType_UserSystemClock, &t_after);
        loop++;

        /* ---- Sleep/Wake 检测 ---- */
        if (loop > 5 && g_net_up && (t_after - t_before) > 5) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "Sleep/wake detected (%llus jump), waiting for WiFi...",
                     (unsigned long long)(t_after - t_before));
            log_msg(msg);
            tunnel_notify_wake();
            http_restart();
            nifm_fail_count = 0;
            continue;
        }

        /* ---- 每 5 秒：检查 HTTP server + 处理远程命令 + 更新状态 ---- */
        if (g_net_up && (loop % 5 == 0)) {
            if (!http_server_is_running()) {
                log_msg("HTTP server down, reinitializing network...");
                http_restart();
                nifm_fail_count = 0;
                continue;
            }

            /* 更新隧道状态（供心跳上报） */
            update_tunnel_status();

            /* 从队列取出并执行命令（串行） */
            TunnelCommand cmd;
            int remaining;
            do {
                remaining = tunnel_dequeue_cmd(&cmd);
                if (cmd.type != TUNNEL_CMD_NONE) {
                    execute_tunnel_cmd(&cmd);
                }
            } while (remaining > 0);
        }

        /* ---- 每 10 秒：检查 nifm 连通性 ---- */
        if (g_net_up && (loop % 10 == 0)) {
            u32 ipaddr = 0;
            Result nifm_rc = nifmGetCurrentIpAddress(&ipaddr);
            if (R_FAILED(nifm_rc)) {
                nifm_fail_count++;
                if (nifm_fail_count >= 3) {
                    log_msg("nifm unresponsive (3 failures), reinitializing...");
                    http_restart();
                    nifm_fail_count = 0;
                    continue;
                }
            } else {
                nifm_fail_count = 0;
            }
        }

        /* ---- 网络未初始化时持续重试 ---- */
        if (!g_net_up && s_base_ready && (loop % 30 == 0)) {
            rc = net_init();
            if (R_SUCCEEDED(rc)) {
                log_msg("Network init succeeded on retry!");
            }
        }

        /* ---- 每 60 秒检查 HTTP server 存活 ---- */
        if (g_net_up && (loop % 60 == 0) && !http_server_is_running()) {
            log_msg("HTTP server down (periodic check), reinitializing...");
            http_restart();
            nifm_fail_count = 0;
        }

        /* ---- 每 300 秒检查 IP 变化 ---- */
        if (g_net_up && (loop - last_ip_check >= 300)) {
            char new_ip[64] = {0};
            u32 a = 0;
            if (R_SUCCEEDED(nifmGetCurrentIpAddress(&a)) && a != 0) {
                ip_to_str(a, new_ip, sizeof(new_ip));
            }
            if (new_ip[0] && strcmp(last_ip, new_ip) != 0) {
                char m[256];
                snprintf(m, sizeof(m), "IP changed: %s -> %s",
                         last_ip[0] ? last_ip : "(none)", new_ip);
                log_msg(m);
                strcpy(last_ip, new_ip);
                {
                    char u[256];
                    snprintf(u, sizeof(u), "Web UI: http://%s:%d", new_ip, HTTP_PORT);
                    log_msg(u);
                }
            }
            last_ip_check = loop;
        }
    }
    return 0;
}
