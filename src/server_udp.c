#include "server.h"
#include "server_udp.h"
#include "server_udp_stream.h"
#include "common.h"
#include "session.h"

#include <stdio.h>
#include <ev.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <quicly.h>
#include <quicly/defaults.h>
#include <unistd.h>

#include <stdbool.h>

#include <quicly/streambuf.h>

#include <picotls/openssl.h>
#include <picotls/../../t/util.h>

extern quicly_context_t server_ctx;

extern session_t *ht_udp_to_quic;
extern session_t *ht_quic_to_flow;

void server_process_udp_packet(char *buf, ssize_t len)
{
    struct iphdr *iph = (struct iphdr *) buf;

    if (iph->protocol != IPPROTO_UDP) {
        log_warn("tun device received non UDP packets (proto: %d) \n", iph->protocol);
        return;
    }

    struct udphdr *udph = (struct udphdr *)(buf + iph->ihl * 4);
    struct sockaddr_in src, dst;
    bzero(&src, sizeof(src));
    bzero(&dst, sizeof(dst));

    src.sin_family = dst.sin_family = AF_INET;
    src.sin_addr.s_addr = iph->saddr;
    src.sin_port = udph->source;
    dst.sin_addr.s_addr = iph->daddr;
    dst.sin_port = udph->dest;

    request_t *req = (request_t *) malloc(sizeof(request_t));
    bzero(req, sizeof(request_t));
    //we need swap the dst and src for downlink to look for the session info.
    memcpy(&(req->da), (void *) &src, sizeof(struct sockaddr_in));
    memcpy(&(req->sa), (void *) &dst, sizeof(struct sockaddr_in));
    req->protocol = IPPROTO_UDP;

    session_t *session = find_session_u2q(&ht_udp_to_quic, req);

    if (!session) {
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, src_ip, sizeof(src_ip));
        log_error("received %ld bytes from %s:%d, but could not find stream to write.\n",
               len, src_ip, ntohs(udph->source));
        free(req);
        return;
    }

    quicly_stream_t *stream = session->stream;

    log_debug("writting to quicly streambuf %ld, len: %ld.\n", session->stream->stream_id, len);
    quicly_streambuf_egress_write(session->stream, buf, len);

    free(req);
    return;
}

void server_tun_read_cb(EV_P_ ev_io *w, int revents)
{
    int fd = w->fd;
    ssize_t read_bytes = 0, total_read_bytes = 0;
    char buf[4096];
    bzero(buf, sizeof(buf));

    while ((read_bytes = read(fd, buf, sizeof(buf))) > 0) {
        //process readed packets;
        server_process_udp_packet(buf, read_bytes);
        total_read_bytes += read_bytes;
    }

    if (read_bytes == 0) {
        log_warn("tun device (fd: %d) is closed.\n", fd);
        ev_io_stop(EV_DEFAULT, w);
        close(fd);
        return;
    }

    if (read_bytes < 0 && errno != EAGAIN) {
        //close tun dev and stop the watcher;
        log_warn("tun device %d read failed with %d, \"%s\". \n",
                    fd, errno, strerror(errno));
        ev_io_stop(EV_DEFAULT, w);
        close(fd);
    }

    return;
}
