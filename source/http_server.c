/**
 * http_server.c - Minimal HTTP server for Switch parental control
 *
 * REST API:
 *   GET  /              -> Embedded HTML UI
 *   GET  /api/status    -> JSON: {daily_limit_min, remaining_min, played_min, today, today_name, version}
 *   POST /api/allow     -> Add minutes to today's limit (additive)
 *                          body: minutes=N
 *                          calc: new_limit = current_limit + N
 *   Version: v1.3
 */
#include "http_server.h"
#include "pctl_handler.h"
#include "heartbeat_client.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

/* Forward declaration — defined in main.c. NOT variadic! */
extern void log_msg(const char *msg);

/* ------------------------------------------------------------------ */
/* State                                                               */
/* ------------------------------------------------------------------ */
static int       s_server_fd = -1;
static volatile int s_client_fd = -1;   /* current client fd, closed by stop() to unblock I/O */
static bool      s_running   = false;
static pthread_t s_thread;
static volatile int s_generation = 0;  /* bumped on each restart */
static volatile bool s_thread_active = false;  /* true after pthread_create, false after thread exits */

/* ------------------------------------------------------------------ */
/* HTTP helpers                                                        */
/* ------------------------------------------------------------------ */
static void http_send(int fd, const char *status, const char *ctype, const char *body)
{
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Connection: close\r\n"
        "Content-Length: %d\r\n"
        "\r\n",
        status, ctype, (int)strlen(body));
    write(fd, header, hlen);
    write(fd, body, strlen(body));
}

static int http_read_request(int fd, char *buf, int bufsize)
{
    int total = 0;
    while (total < bufsize - 1) {
        int n = read(fd, buf + total, bufsize - 1 - total);
        if (n <= 0) break;
        total += n;
        buf[total] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
    }
    return total;
}

/* ------------------------------------------------------------------ */
/* API handlers                                                        */
/* ------------------------------------------------------------------ */
static u32 clamp_remaining_min(u64 remaining_ns)
{
    if (remaining_ns == 0)
        return 0;
    if (remaining_ns > 86400000000000ULL)
        return 0;
    return (u32)NS_TO_MINUTES(remaining_ns);
}

static void api_status(int fd)
{
    u64 remaining_ns = 0;
    u32 daily_limit  = 0;
    u32 remaining_min = 0;
    u32 played_min    = 0;
    int today = 0;

    tunnel_pctl_lock();
    Result rc = pctl_init();
    if (R_SUCCEEDED(rc)) {
        pctl_get_remaining_time(&remaining_ns);
        pctl_get_daily_limit_minutes(&daily_limit);
        remaining_min = clamp_remaining_min(remaining_ns);
        played_min    = (daily_limit > remaining_min) ? (daily_limit - remaining_min) : 0;
        today = pctl_get_today_day();
        pctl_exit();
    }
    tunnel_pctl_unlock();

    char json[256];
    static const char *day_names[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    snprintf(json, sizeof(json),
        "{\"daily_limit_min\":%u,\"remaining_min\":%u,\"played_min\":%u,\"today\":%d,\"today_name\":\"%s\",\"version\":\"v1.7.1\"}",
        daily_limit, remaining_min, played_min, today, day_names[today]);

    http_send(fd, "200 OK", "application/json", json);
}

static void api_allow(int fd, const char *body)
{
    int allow_min = 0;
    const char *p = strstr(body, "minutes");
    if (p) {
        p = strchr(p + 7, '=');
        if (p) allow_min = atoi(p + 1);  /* 支持负数：减时间 */
    }

    tunnel_pctl_lock();
    Result rc = pctl_init();
    if (R_FAILED(rc)) {
        tunnel_pctl_unlock();
        http_send(fd, "200 OK", "application/json", "{\"success\":0,\"error\":\"pctl_init_failed\"}");
        return;
    }

    int today = pctl_get_today_day();

    if (allow_min == 0) {
        rc = pctl_set_day_limit_minutes(today, 0);
    } else {
        u32 daily_limit = 0;
        pctl_get_daily_limit_minutes(&daily_limit);

        /* 用 int 计算，支持负数减时间，然后 clamp 到 [0, 1440] */
        int new_limit = (int)daily_limit + allow_min;
        if (new_limit < 0) new_limit = 0;
        if (new_limit > 1440) new_limit = 1440;

        rc = pctl_set_day_limit_minutes(today, (u32)new_limit);
        /* 修改限额后重启计时器，强制系统用新限额重新计算剩余时间 */
        if (R_SUCCEEDED(rc)) {
            pctl_stop_play_timer();
            pctl_start_play_timer();
        }
    }

    pctl_exit();
    tunnel_pctl_unlock();

    char json[128];
    snprintf(json, sizeof(json),
        "{\"success\":%d}",
        R_SUCCEEDED(rc) ? 1 : 0);

    http_send(fd, "200 OK", "application/json", json);
}

/* Embedded Web UI                                                     */
/* ------------------------------------------------------------------ */
static const char *WEB_HTML =
"<!DOCTYPE html>"
"<html>"
"<head>"
"<meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>Switch Timer v1.7.1</title>"
"<style>"
"body{font-family:sans-serif;background:#1a1a2e;color:#fff;text-align:center;padding:20px;margin:0}"
".box{background:rgba(255,255,255,0.1);border-radius:12px;padding:20px;margin:15px 0}"
".big{font-size:2.5em;font-weight:bold;margin:10px 0}"
".lbl{color:rgba(255,255,255,0.6);font-size:0.9em}"
".row{display:flex;gap:10px;justify-content:center;margin:15px 0}"
".tile{flex:1;background:rgba(255,255,255,0.08);border-radius:10px;padding:14px}"
"input{width:90px;font-size:1.5em;text-align:center;padding:8px;border:none;border-radius:8px;background:rgba(255,255,255,0.15);color:#fff}"
".btns{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin:12px 0}"
"button{font-size:1em;padding:10px 18px;border:none;border-radius:8px;background:#3b82f6;color:#fff;cursor:pointer}"
"button:active{transform:scale(0.95)}"
".btn-sm{background:#374151;font-size:0.9em;padding:8px 14px}"
".btn-minus{background:#7f1d1d;font-size:0.9em;padding:8px 14px}"
"#msg{margin-top:8px;color:#fbbf24;font-size:0.9em;min-height:20px}"
".badge{display:inline-block;background:#10b981;color:#fff;font-size:0.7em;padding:2px 8px;border-radius:10px;margin-left:8px}"
"</style>"
"</head>"
"<body>"
"<h2>Switch Parental Control <small>v1.7.1</small> <span class='badge'>LAN + Remote</span></h2>"
"<div class='box'>"
"<div class='row'>"
"<div class='tile'><div class='lbl'>Played</div><div class='big' id='played'>--</div></div>"
"<div class='tile'><div class='lbl'>Remaining</div><div class='big' id='remain'>--</div></div>"
"</div>"
"<div class='lbl' style='margin-top:4px'>Limit: <span id='limit'>--</span> min</div>"
"</div>"
"<div class='box'>"
"<div class='lbl'>Allow to play (minutes)</div>"
"<input type='number' id='min' value='30' min='-1440' max='1440'>"
"<br>"
"<div class='btns'>"
"<button class='btn-minus' onclick='quickSet(-30)'>-30</button>"
"<button class='btn-minus' onclick='quickSet(-10)'>-10</button>"
"<button class='btn-sm' onclick='quickSet(15)'>+15</button>"
"<button class='btn-sm' onclick='quickSet(30)'>+30</button>"
"<button class='btn-sm' onclick='quickSet(60)'>+60</button>"
"<button class='btn-sm' onclick='quickSet(90)'>+90</button>"
"</div>"
"<button onclick='allow()'>Confirm</button>"
"<div id='msg'></div>"
"</div>"
"<script>"
"function load(){"
"fetch('/api/status').then(r=>r.json()).then(d=>{"
"document.getElementById('limit').textContent=d.daily_limit_min;"
"document.getElementById('remain').textContent=d.remaining_min+'m';"
"document.getElementById('played').textContent=d.played_min+'m';"
"}).catch(()=>{document.getElementById('msg').textContent='Load failed'});"
"}"
"function quickSet(m){"
"document.getElementById('min').value=m;"
"}"
"function allow(){"
"var m=parseInt(document.getElementById('min').value)||0;"
"document.getElementById('msg').textContent='Saving...';"
"fetch('/api/allow',{method:'POST',body:'minutes='+m}).then(r=>r.json()).then(d=>{"
"document.getElementById('msg').textContent=d.success?'Done!':'Failed';"
"setTimeout(function(){document.getElementById('msg').textContent='';load();},1200);"
"}).catch(()=>{document.getElementById('msg').textContent='Error'});"
"}"
"load();"
"setInterval(load,30000);"
"</script>"
"</body>"
"</html>";

/* ------------------------------------------------------------------ */
/* Route dispatcher                                                    */
/* ------------------------------------------------------------------ */
static void handle_request(int fd)
{
    char buf[2048];
    int n = http_read_request(fd, buf, sizeof(buf));
    if (n <= 0) { close(fd); return; }

    char method[16] = {0}, path[256] = {0};
    sscanf(buf, "%15s %255s", method, path);

    if (strcmp(method, "OPTIONS") == 0) {
        http_send(fd, "204 No Content", "text/plain", "");
        close(fd);
        return;
    }

    char *body = strstr(buf, "\r\n\r\n");
    if (body) body += 4;

    if (strcmp(path, "/") == 0 && strcmp(method, "GET") == 0) {
        http_send(fd, "200 OK", "text/html; charset=utf-8", WEB_HTML);
    } else if (strcmp(path, "/api/status") == 0) {
        api_status(fd);
    } else if (strcmp(path, "/api/allow") == 0 && strcmp(method, "POST") == 0) {
        api_allow(fd, body ? body : "");
    } else {
        http_send(fd, "404 Not Found", "application/json", "{\"error\":\"not found\"}");
    }

    close(fd);
}

/* ------------------------------------------------------------------ */
/* Server thread                                                       */
/* ------------------------------------------------------------------ */
static void *http_thread_func(void *arg)
{
    (void)arg;
    int gen = s_generation;

    /* Capture the server fd for this generation — once captured, it never
     * becomes -1 even if http_server_stop() sets s_server_fd = -1.
     * This prevents FD_SET(-1) undefined behavior. */
    int my_server_fd = s_server_fd;

    while (s_running) {
        if (s_generation != gen) break;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(my_server_fd, &rfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 500000;

        int ret = select(my_server_fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0 || s_generation != gen) {
            s_running = false;
            break;
        }
        if (ret == 0) continue;

        if (FD_ISSET(my_server_fd, &rfds)) {
            if (s_generation != gen) break;
            int client_fd = accept(my_server_fd, NULL, NULL);
            if (client_fd < 0 || s_generation != gen) {
                if (client_fd >= 0) close(client_fd);
                s_running = false;
                break;
            }
            s_client_fd = client_fd;      /* track so stop() can close it */
            handle_request(client_fd);
            s_client_fd = -1;             /* done with this client */
        }
    }

    s_thread_active = false;  /* 线程退出时清除标志 */
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void http_server_start(void)
{
    struct sockaddr_in addr;

    if (s_server_fd >= 0) {
        close(s_server_fd);
        s_server_fd = -1;
    }

    /* Wait for any previous thread to finish — it sets s_thread_active = false
     * on exit.  We DON'T pthread_join because that can cause 2168-0002 if
     * the thread is still in a blocking syscall.  The thread is created
     * detached, so its resources are auto-reclaimed. */
    if (s_thread_active) {
        for (int i = 0; i < 30 && s_thread_active; i++) {
            svcSleepThread(100000000ULL);  /* 100ms, up to 3s total */
        }
        if (s_thread_active) {
            log_msg("http_server_start: previous thread still active, proceeding anyway");
        }
        s_thread_active = false;
    }

    s_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s_server_fd < 0) {
        log_msg("http_server_start: socket() failed");
        return;
    }

    int optval = 1;
    setsockopt(s_server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(HTTP_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_msg("http_server_start: bind() failed");
        close(s_server_fd);
        s_server_fd = -1;
        return;
    }

    if (listen(s_server_fd, 4) < 0) {
        log_msg("http_server_start: listen() failed");
        close(s_server_fd);
        s_server_fd = -1;
        return;
    }

    s_running = true;
    s_generation++;

    /* Create thread as DETACHED — no pthread_join needed, resources auto-freed.
     * This eliminates the 2168-0002 crash that occurs when pthread_join() is
     * called on a thread that's still in a blocking syscall. */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 0x10000);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&s_thread, &attr, http_thread_func, NULL);
    s_thread_active = true;
    pthread_attr_destroy(&attr);

    log_msg("http_server_start: OK");
}

void http_server_stop(void)
{
    s_running = false;

    /* Shut down the client socket — shutdown(SHUT_RDWR) breaks the connection
     * and unblocks any read()/write() the thread may be blocked on, but does
     * NOT close the fd.  The thread will close it when handle_request()
     * returns.  This avoids the fd-reuse race where close() frees the fd
     * number and a new socket grabs it before the thread's own close(). */
    if (s_client_fd >= 0) {
        shutdown(s_client_fd, SHUT_RDWR);
    }

    /* Close the server socket to unblock select()/accept(). */
    if (s_server_fd >= 0) {
        int fd = s_server_fd;
        s_server_fd = -1;
        close(fd);
    }

    /* Wait for the thread to exit (it sets s_thread_active = false on exit).
     * With the client shutdown and server closed, the thread should exit
     * quickly.  We do NOT call pthread_join() — the thread is detached, so
     * its resources are auto-reclaimed.  Calling join on a thread still in
     * a blocking syscall causes the 2168-0002 crash on Horizon OS. */
    if (s_thread_active) {
        for (int i = 0; i < 30 && s_thread_active; i++) {
            svcSleepThread(100000000ULL);  /* 100ms, up to 3s */
        }
        if (s_thread_active) {
            log_msg("http_server_stop: thread did not exit in 3s (detached, will clean up later)");
        }
        s_thread_active = false;
    }
}

bool http_server_is_running(void)
{
    return s_running;
}
