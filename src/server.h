#pragma once

#include <quicly.h>
#include <stdbool.h>

#include "common.h"

session_t *hash_find_by_tcp_fd(int fd);
session_t *hash_find_by_stream_id(long int stream_id);
void hash_insert(session_t *s);
void hash_del(session_t *s);


