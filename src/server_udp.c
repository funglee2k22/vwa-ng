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

extern ssize_t streambuf_high_watermarker;

extern quicly_context_t server_ctx;

extern session_t *ht_udp_to_quic;
extern session_t *ht_quic_to_flow;


request_t *get_request(char *buf, struct sockaddr_in *src, struct sockaddr_in *dst)
{
    struct iphdr *iph = (struct iphdr *) buf;
    struct udphdr *udph = (struct udphdr *)(buf + iph->ihl * 4);

    src->sin_family = dst->sin_family = AF_INET;
    src->sin_addr.s_addr = iph->saddr;
    src->sin_port = udph->source;
    dst->sin_addr.s_addr = iph->daddr;
    dst->sin_port = udph->dest;

    request_t *req = (request_t *) malloc(sizeof(request_t));
    bzero(req, sizeof(request_t));
    //we need swap the dst and src for downlink to look for the session info.
    memcpy(&(req->da), (void *) src, sizeof(struct sockaddr_in));
    memcpy(&(req->sa), (void *) dst, sizeof(struct sockaddr_in));
    req->protocol = IPPROTO_UDP;

    return req;
}

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

    //req here only used to find session.
    request_t *req = get_request(buf, &src, &dst);
    session_t *session = find_session_u2q(&ht_udp_to_quic, req);

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    unsigned short sport = ntohs(udph->source), dport = ntohs(udph->dest);
    inet_ntop(AF_INET, &iph->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &iph->daddr, dst_ip, sizeof(dst_ip));

    if (!session) {
        log_warn("received %ld bytes %s:%d -> %s:%d, but could not find stream to write.\n",
                  len, src_ip, sport, dst_ip, dport);
        free(req);
        return;
    }

    quicly_stream_t *stream = session->stream;
    ssize_t qlen = estimate_quicly_stream_egress_qlen(stream);

    if (qlen > streambuf_high_watermarker) {
        // if a large backlog, just throw the udp packet away.
        log_debug("stream %ld qlen %ld too large, and drop %ld bytes udp packets.\n",
                       session->stream_id, qlen, len);
        session->stats.dropped_udp_pkts += 1;
        session->stats.dropped_udp_bytes += len;
    } else {
        log_debug("udp %s:%d -> %s:%d writting to quicly stream %ld, len: %ld.\n",
              src_ip, sport, dst_ip, dport, \
              session->stream->stream_id, len);
        quicly_streambuf_egress_write(session->stream, buf, len);
    }

    free(req);

    return;
}

void server_tun_read_cb(EV_P_ ev_io *w, int revents)
{
    int fd = w->fd;
    ssize_t read_bytes = 0, total_read_bytes = 0;
    char buf[4096];
    bzero(buf, sizeof(buf));
    struct iphdr *iph = (struct iphdr *) buf;
    while ((read_bytes = read(fd, buf, sizeof(buf))) > 0) {
        //process readed packets;
        ssize_t ip_total_len = ntohs(iph->tot_len);
        if (ip_total_len < read_bytes)
            log_debug("tun device read pkt with padding, %ld bytes, actual %ld.\n", read_bytes, ip_total_len);
        assert(ip_total_len <= read_bytes);
        server_process_udp_packet(buf, ip_total_len);
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
