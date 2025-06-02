#pragma once

#include "uthash.h"

#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <quicly.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

#define APP_BUF_SIZE (1 * 1024 * 1024)

typedef struct session {
    long int stream_id;      // on both client and server, stream_id is the key
    int fd;
    struct sockaddr_in sa;   // TCP socket src addr
    struct sockaddr_in da;   // TCP socket original dst addr
    quicly_conn_t *conn;     // quicly_conn_t *conn used by quicly stream
    union {
        bool ctrl_frame_received;
        bool ctrl_frame_sent;
    };
    void *t2q_buf;
    void *q2t_buf;
    size_t buf_len;
    size_t t2q_read_offset;
    size_t t2q_write_offset;
    size_t q2t_read_offset;
    size_t q2t_write_offset;
    UT_hash_handle hh_t2q;    //uthash requires different handle for each hashmap
    UT_hash_handle hh_q2t;    //
} session_t;

void add_to_hash_t2q(session_t **hh, session_t *s);

session_t *find_session_t2q(session_t **hh, int fd);

void add_to_hash_q2t(session_t **hh, session_t *s);

session_t *find_session_q2t(session_t **hh, long int stream_id);

void delete_session(session_t **t2q, session_t **q2t, session_t *s);
