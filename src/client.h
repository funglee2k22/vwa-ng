#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "common.h"

#define USE_EV_EVENT_FEED

void quit_client();

session_t *hash_find_by_tcp_fd(int fd);
session_t *hash_find_by_stream_id(long int stream_id);
void hash_insert(session_t *s);
void hash_del(session_t *s);

void client_cleanup(int fd);

