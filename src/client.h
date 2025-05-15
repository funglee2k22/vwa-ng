#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "common.h"

void quit_client();

//Session HashTable Related
//void add_session(session_t *t);
//session_t *find_session(long int stream_id); 
//void del_session(long int stream_id);

#define HASH_SIZE 1024
session_t *hash_find_by_tcp_fd(int fd);
session_t *hash_find_by_stream_id(long int stream_id);
void hash_insert(session_t *s);
void hash_del(session_t *s);

void client_cleanup(int fd);

