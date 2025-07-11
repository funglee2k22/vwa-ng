#pragma once

#include <quicly.h>
#include <sys/socket.h>

quicly_error_t udp_client_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);

void udp_client_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);

