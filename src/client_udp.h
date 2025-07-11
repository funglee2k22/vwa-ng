#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "common.h"
#include <quicly.h>

int open_tun_dev(const char *devname);
int create_udp_raw_socket(int tun_fd);
void process_udp_packet(char *buf, ssize_t len);
void client_tun_read_cb(EV_P_ ev_io *w, int revents);
