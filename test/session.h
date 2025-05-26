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
    UT_hash_handle hh_t2q;  
    UT_hash_handle hh_q2t; 
    //should be ev_timer     // TODO  it should be a timer handle. 
    void *data; 
    ssize_t read_offset; 
    ssize_t write_offset; 
    ssize_t max_length;
} session_t; 
