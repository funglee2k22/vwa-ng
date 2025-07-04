#pragma once

#include <ev.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <quicly.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include "uthash.h"

#define APP_BUF_SIZE (1 * 1024 * 1024)

typedef struct session {
    struct timeval start_tm;
    bool first_read_quic;
    bool first_read_tcp;
    long int stream_id;      // on both client and server, stream_id is the key
    int fd;
    quicly_stream_t *stream;
    bool stream_active;
    bool tcp_active;
    struct sockaddr_in sa;   // TCP socket src addr
    struct sockaddr_in da;   // TCP socket original dst addr
    quicly_conn_t *conn;     // quicly_conn_t *conn used by quicly stream
    union {
        bool ctrl_frame_received;
        bool ctrl_frame_sent;
    };
    ev_io *tcp_read_watcher;
    ev_io *tcp_write_watcher;
    UT_hash_handle hh_t2q;    //uthash requires different handle for each hashmap
    UT_hash_handle hh_q2t;    //
} session_t;

extern struct ev_loop *loop;

void add_to_hash_t2q(session_t **hh, session_t *s);
session_t *find_session_t2q(session_t **hh, int fd);
void add_to_hash_q2t(session_t **hh, session_t *s);
session_t *find_session_q2t(session_t **hh, long int stream_id);

void delete_session_init_from_tcp(session_t *s, int errno);
void delete_session_init_from_quic(session_t *s, quicly_error_t);

void close_quic_stream_in_session(session_t *s, quicly_error_t err);

void terminate_quic_stream(quicly_stream_t *stream, quicly_error_t err);

void close_tcp_conn(session_t *s);




