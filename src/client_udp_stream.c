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
extern session_t *ht_quic_to_udp;
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
        log_warn("attempt to write non-udp ip packets.\n");
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
    log_info("ok\n");

    if (len == 0)
        return;

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0) {
        return;
    }

    log_debug("stream %ld received %ld bytes.\n", stream->stream_id, len);
    //TODO write the received data to original CPE through a raw IP/UDP packets.

    int ret = write_to_udp_raw_socket(client_udp_raw_fd, (char *) input.base, input.len);

    if (ret < 0 && errno != EAGAIN) {
        //FIXME we should close this stream and remove session info from httables.
        log_error("stream %ld, send raw udp packet failed w/ errno %d, \"%s\"\n",
                    stream->stream_id, errno, strerror(errno));
    }

    quicly_stream_sync_recvbuf(stream, len);
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

