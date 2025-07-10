#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "common.h"
#include <quicly.h>

/* hash table handling */
void add_to_hash_u2q(session_t **hh, session_t *s);
void add_to_hash_q2u(session_t **hh, session_t *s);
session_t *find_session_u2q(session_t **hh, request_t *req);
session_t *find_session_q2u(session_t **hh, quicly_stream_t *stream);
void delete_session_u2q(session_t **hh, session_t *s); 
void delete_session_q2u(session_t **hh, session_t *s);

int open_tun_dev(const char *devname);
int create_udp_raw_socket(int tun_fd);
void process_udp_packet(char *buf, ssize_t len);
void client_tun_read_cb(EV_P_ ev_io *w, int revents);




