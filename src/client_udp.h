#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "common.h"
#include <quicly.h>

void process_udp_packet(char *buf, ssize_t len);
void client_tun_read_cb(EV_P_ ev_io *w, int revents);

int create_udp_connection(struct sockaddr_in *dst);


