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
#include "common.h"
#include "uthash.h"

#define APP_BUF_SIZE (1 * 1024 * 1024)

typedef struct request {
    struct sockaddr_in sa;   // socket src addr
    struct sockaddr_in da;   // socket original dst addr
    u_int8_t protocol;       // protocol IPPROTO_UDP or IPPROTO_TCP
} request_t;

typedef struct _st_stream_key {
    quicly_conn_t *conn;
    long int stream_id;
} stream_key_t;

typedef struct _stats {
    ssize_t dropped_udp_pkts;
    ssize_t dropped_udp_bytes;
    ssize_t sent_udp_pkts;
    ssize_t sent_udp_bytes;
    ssize_t total_udp_pkts;
    ssize_t total_udp_bytes;
} session_stats_t;

typedef struct session {
    struct timeval start_tm;
    struct timeval active_tm;    //used for UDP session cleanup
    bool first_read_quic;
    bool first_read_tcp;
    long int stream_id;      // on both client and server, stream_id is the key
    int fd;
    int raw_udp_fd;
    quicly_stream_t *stream;
    bool stream_active;
    bool tcp_active;
    quicly_conn_t *conn;     // quicly_conn_t *conn used by quicly stream
    union {
        bool ctrl_frame_received;
        bool ctrl_frame_sent;
    };

    session_stats_t stats;

    request_t req;
    ev_io *tcp_read_watcher;
    ev_io *tcp_write_watcher;

    UT_hash_handle hh_t2q;    //uthash requires different handle for each hashmap
    UT_hash_handle hh_u2q;    // use UDP five tuples to find QUIC Stream
    UT_hash_handle hh_q2f;    // use quicly stream to find tcp and/or udp for given stream
} session_t;

void print_session_event(session_t *s, const char *fmt, ...)
          __attribute__((format(printf, 2, 3)));

extern struct ev_loop *loop;

//TCP based session disconnect handling
void delete_session_init_from_tcp(session_t *s, int errno);
void delete_session_init_from_quic(session_t *s, quicly_error_t);

void close_tcp_conn(session_t *s);

void close_quic_stream_in_session(session_t *s, quicly_error_t err);
void terminate_quic_stream(quicly_stream_t *stream, quicly_error_t err);

// hash table handling for UDP/TCP side to QUIC side.
void add_to_hash_t2q(session_t **hh, session_t *s);
void add_to_hash_u2q(session_t **hh, session_t *s);
session_t *find_session_t2q(session_t **hh, int fd);
session_t *find_session_u2q(session_t **hh, request_t *req);

void delete_session_u2q(session_t **hh, session_t *s);
void delete_session_t2q(session_t **hh, session_t *s);
void delete_session_q2f(session_t **hh, session_t *s);

//quic to tcp/udp share the same hash table
void add_to_hash_q2f(session_t **hh, session_t *s);
session_t *find_session_q2f(session_t **hh, quicly_stream_t *stream);

void remove_inactive_udp_sessions();
void client_remove_inactive_udp_sessions(void);



