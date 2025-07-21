#pragma once


#include "session.h" 

#include <quicly.h>
#include <sys/socket.h>


session_t *create_udp_session(quicly_stream_t *stream, request_t *req); 

void server_stream_udp_receive(session_t *session); 

