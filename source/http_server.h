/**
 * http_server.h - Lightweight HTTP server for pctltcp-web
 */

#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <switch.h>

#define HTTP_PORT  8081

void http_server_start(void);    /* Create thread + bind socket */
void http_server_stop(void);     /* Final shutdown only */
void http_server_restart(void);  /* Rebind socket, thread keeps running */
bool http_server_is_running(void);

#endif /* HTTP_SERVER_H */
