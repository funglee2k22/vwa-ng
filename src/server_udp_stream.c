#include "server_udp_stream.h"
#include "server.h"
#include "common.h"
#include "session.h"

#include <ev.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <quicly.h>
#include <quicly/streambuf.h>
#include <sys/time.h>

extern session_t *ht_tcp_to_quic;
extern session_t *ht_udp_to_quic;
extern session_t *ht_quic_to_flow;

extern int server_udp_raw_fd;

session_t *create_udp_session(quicly_stream_t *stream, request_t *req)
{
    session_t *ns = (session_t *) malloc(sizeof(session_t));
    bzero(ns, sizeof(session_t));

    memcpy(&(ns->req), req, sizeof(request_t));
    ns->stream = stream;
    ns->conn = stream->conn;
    ns->stream_id = stream->stream_id;

    gettimeofday(&ns->start_tm, NULL);
    gettimeofday(&ns->active_tm, NULL);

    //note, for udp server side still use tun dev and raw sockets.
    ns->fd = ns->raw_udp_fd = server_udp_raw_fd;

    add_to_hash_u2q(&ht_udp_to_quic, ns);  //key is req
    add_to_hash_q2f(&ht_quic_to_flow, ns); //key is the stream

    return ns;
}


void server_stream_udp_receive(session_t *session)
{
    quicly_stream_t *stream = session->stream;

    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    if (input.len == 0) {
        log_warn("stream %ld, have no data in its receive buff.\n", stream->stream_id);
        return;
    }

    log_debug("stream: %ld, recv buf has %ld bytes available for UDP traffic.\n",
                stream->stream_id, input.len);

    int raw_sock = session->raw_udp_fd;
    ssize_t bytes_sent = 0, total_bytes_sent = 0;
    struct sockaddr_in dest;
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = session->req.da.sin_addr.s_addr;
    dest.sin_port = session->req.da.sin_port;

    do {
        struct iphdr *iph = (struct iphdr *) (input.base);
        ssize_t ip_total_len = ntohs(iph->tot_len);

        if (ip_total_len > input.len) {
            //too often
            log_debug("stream %ld only have %ld bytes in its buffer while the ip total length %ld bytes.\n",
                     stream->stream_id, input.len, ip_total_len);
            break;
        }

        bytes_sent = sendto(raw_sock, iph, ip_total_len, 0, (struct sockaddr *)&dest, sizeof(dest));

        if (bytes_sent < 0) {
            log_error("stream id %ld write %ld bytes to raw_sock %d failed w/ errno %d, \"%s\".\n",
                     stream->stream_id, input.len, raw_sock, errno, strerror(errno));
            //raw socket should be leave open
            break;
        }

        if (bytes_sent < ip_total_len) {
            log_error("stream %ld writes partial packets (%ld of %ld bytes) into raw socket %d.\n",
                      stream->stream_id, bytes_sent, ip_total_len, raw_sock);
          //because of no retransmission,  we only gives warning here.
        }

        total_bytes_sent += ip_total_len;
        input.base += ip_total_len;
        input.len -= ip_total_len;

    } while (input.len > 0);

    if (total_bytes_sent > 0) {
        if (input.len > 0)
            quicly_streambuf_ingress_shift(stream, total_bytes_sent);
        else
            quicly_stream_sync_recvbuf(stream, total_bytes_sent);
        log_debug("stream %ld wrote %ld bytes to %s:%d through raw sock %d.\n",
                    stream->stream_id, total_bytes_sent, inet_ntoa(dest.sin_addr),
                    ntohs(dest.sin_port), raw_sock);
    }

    if (bytes_sent < 0) {
        if (errno != EAGAIN) {
          log_error("stream id %ld wrote to raw_sock %d failed w/ errno %d, \"%s\".\n",
                     stream->stream_id, raw_sock, errno, strerror(errno));
        } else {
          log_error("stream id %ld wrote to raw_sock %d failed w/ errno %d, \"%s\".\n",
                     stream->stream_id, raw_sock, errno, strerror(errno));
       }
    }

    return;
}



