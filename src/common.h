#pragma once

#include "uthash.h"

#include <quicly.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

typedef struct cpep_session { 
    long int stream_id;      // on both client and server, stream_id is the key 
    int fd; 
    struct sockaddr_in sa;   // TCP socket src addr 
    struct sockaddr_in da;   // TCP socket original dst addr 
    quicly_conn_t *conn;     // quicly_conn_t *conn used by quicly stream
    //should be ev_timer     // TODO  it should be a timer handle. 
    UT_hash_handle hh; 
} session_t; 

typedef struct cpep_frame { 
    int type; 
    union { 
        session_t s; 
	char  payload[4096];
    };
} frame_t; 

ptls_context_t *get_tlsctx();

struct addrinfo *get_address(const char *host, const char *port);
bool send_pending(quicly_context_t *ctx, int fd, quicly_conn_t *conn);

int set_non_blocking(int sockfd);

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
