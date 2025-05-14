#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "common.h"

void quit_client();

//Session HashTable Related
void add_session(session_t *t);
session_t *find_session(long int stream_id); 
void del_session(long int stream_id);


void client_cleanup(int fd);

