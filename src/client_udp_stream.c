#include "client_udp_stream.h"
#include "client.h"
#include "common.h"
#include <ev.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <quicly/streambuf.h>

extern session_t *ht_udp_to_quic;
extern session_t *ht_quic_to_flow;
extern int client_udp_raw_fd;

static void udp_client_stream_send_stop(quicly_stream_t *stream, quicly_error_t err)
{
    log_info("stream %ld received STOP_SENDING: %li\n", stream->stream_id, err);
    //FIXME need a new function to handle udp stream disconnection.
}

ssize_t write_to_udp_raw_socket(int raw_sock, char *buf, ssize_t len)
{
    struct sockaddr_in dst_addr;
    struct iphdr *ip_header = (struct iphdr *)buf;

    if (ip_header->protocol != IPPROTO_UDP) {
        log_warn("attempt to write non-udp ip packets iph.protocol: %d.\n", ip_header->protocol);
        return 0;
    }

    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = ip_header->daddr;

    ssize_t nwrite = sendto(raw_sock, buf, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    if (nwrite < 0) {
         log_error("sendto raw socket %d w/ errno %d, \"%s\"", raw_sock, errno, strerror(errno));
         //leave the raw_sock open;
         return nwrite;
    }


    if ((nwrite < len) && (nwrite == ntohs(ip_header->tot_len))) {
        return len;
    }

    return nwrite;
}

void udp_client_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    long int stream_id = stream->stream_id;

    if (len == 0)
        return;

    log_info("stream %ld received %ld bytes.\n", stream->stream_id, len);

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    session_t *session = find_session_q2f(&ht_quic_to_flow, stream);

    if (!session) {
        //ignore this error for udp on client side.
        log_warn("not session info associated with stream %ld.\n", stream->stream_id);
        return;
    }

    int raw_sock = session->raw_udp_fd;

    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    if (input.len == 0) {
        return;
    }

    ssize_t bytes_sent = -1, total_bytes_sent = 0;
    struct sockaddr_in dst_addr;
    bzero(&dst_addr, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = session->req.sa.sin_port;

    do {
        struct iphdr *iph = (struct iphdr *)input.base;
        ssize_t ip_total_len = ntohs(iph->tot_len);
        dst_addr.sin_addr.s_addr = iph->daddr;

        if (ip_total_len > input.len) {
             log_warn("stream %ld only have %ld bytes in its buffer while the ip total length %ld bytes.\n",
                       stream->stream_id, input.len, ip_total_len);
             break;
        }

        bytes_sent  = sendto(raw_sock, input.base, ip_total_len, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));

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

        log_info("stream %ld wrote %ld bytes to %s:%d through raw sock %d.\n",
                    stream->stream_id, total_bytes_sent, inet_ntoa(dst_addr.sin_addr),
                    ntohs(dst_addr.sin_port), raw_sock);
    }

    if (bytes_sent < 0) {
        if (errno != EAGAIN) {
          log_error("stream id %ld wrote to raw_sock %d failed w/ errno %d, \"%s\".\n",
                     stream->stream_id, raw_sock, errno, strerror(errno));
        }
    }

    return;
}

static void udp_client_stream_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    log_info("stream %ld, received RESET_STREAM: %li\n", stream->stream_id, err);
    //FIXME do we need to terminate session here ?
}

static void udp_client_stream_on_destroy(quicly_stream_t *stream, quicly_error_t err)
{
    log_info("stream %ld is destroyed w/ error %ld.\n", stream->stream_id, err);
    quicly_streambuf_destroy(stream, err);
    return;
}

const quicly_stream_callbacks_t udp_client_stream_callbacks = {
    &udp_client_stream_on_destroy,
    &quicly_streambuf_egress_shift,
    &quicly_streambuf_egress_emit,
    &udp_client_stream_send_stop,
    &udp_client_stream_receive,
    &udp_client_stream_receive_reset
};

