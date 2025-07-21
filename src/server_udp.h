#pragma once

#include "common.h"
#include "session.h"

#include <ev.h>
#include <quicly.h>
#include <stdbool.h>


void server_tun_read_cb(EV_P_ ev_io *w, int revents);
