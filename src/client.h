#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "common.h"

#define USE_EV_EVENT_FEED

void quit_client();
void client_cleanup(int fd);

void client_quic_read_cb(EV_P_ ev_io *w, int revents);

int clt_setup_quic_connection(const char *host, const char *port);


