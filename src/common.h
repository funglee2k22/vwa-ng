#pragma once

#include "uthash.h"
#include "session.h"

#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <quicly.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

#define SOCK_READ_BUF_SIZE   4096

int open_tun_dev(const char *devname);

int create_udp_raw_socket(int tun_fd);

ptls_context_t *get_tlsctx();

struct addrinfo *get_address(const char *host, const char *port);
bool send_pending(quicly_context_t *ctx, int fd, quicly_conn_t *conn);

int set_non_blocking(int sockfd);

void _debug_printf(int priority, const char *function, int line, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

void print_stream_event(quicly_stream_t *s, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

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

int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y);
