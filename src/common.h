#pragma once

#include "uthash.h"
#include "session.h"

#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <quicly.h>
#include <quicly/streambuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

#define SOCK_READ_BUF_SIZE 4096

typedef struct cpep_frame {
    int type;
    union {
       struct {
           struct sockaddr_in src;
           struct sockaddr_in dst;     //original
       } s;
    };
} frame_t;

ptls_context_t *get_tlsctx();

struct addrinfo *get_address(const char *host, const char *port);
bool send_pending(quicly_context_t *ctx, int fd, quicly_conn_t *conn);

//EV_WRITE TCP socket handler used by both client and server
void tcp_write_cb(EV_P_ ev_io *w, int revents); 

static inline void quicly_streambuf_ingress_safe_shift(quicly_stream_t *stream, size_t off, size_t delta);

int set_non_blocking(int sockfd);

void _debug_printf(int priority, const char *function, int line, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

void print_trace (void);

#define log_debug(...)  _debug_printf(LOG_DEBUG, __func__, __LINE__, __VA_ARGS__)
#define log_info(...)   _debug_printf(LOG_INFO, __func__, __LINE__, __VA_ARGS__)
#define log_warn(...)   _debug_printf(LOG_WARNING,__func__, __LINE__, __VA_ARGS__)
#define log_error(...)  _debug_printf(LOG_ERR, __func__, __LINE__, __VA_ARGS__)

static inline int64_t min_int64(int64_t a, int64_t b)
{
    if(a < b) {
        return a;
    } else {
        return b;
    }
}

static inline int64_t max_int64(int64_t a, int64_t b) {
    if(a > b) {
        return a;
    } else {
        return b;
    }
}

static inline int64_t clamp_int64(int64_t val, int64_t min, int64_t max)
{
    if(val < min) {
        return min;
    }
    if(val > max) {
        return max;
    }
    return val;
}

static inline uint64_t get_current_pid()
{
    uint64_t pid;

    #ifdef __APPLE__
        pthread_threadid_np(NULL, &pid);
    #else
        pid = syscall(SYS_gettid);
    #endif

    return pid;
}

static char *get_conn_str(struct sockaddr_in *sa, struct sockaddr_in *da, char *out, size_t len)
{
#define TEMP_STR_LEN 64
    char str_src[TEMP_STR_LEN] = {0}, str_dst[TEMP_STR_LEN] = {0};

    snprintf(str_src, sizeof(str_src), "%s:%d",
                      inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));

    snprintf(str_dst, sizeof(str_dst), "%s:%d",
                      inet_ntoa(da->sin_addr), ntohs(da->sin_port));
    snprintf(out, len - 1, "%s -> %s", str_src, str_dst);
    return out;
}


static inline void quicly_streambuf_ingress_safe_shift(quicly_stream_t *stream, size_t off, size_t delta)
{
    if (delta <= off)
         quicly_streambuf_ingress_shift(stream, delta);
    else
         quicly_stream_sync_recvbuf(stream, delta);
    return;
}

