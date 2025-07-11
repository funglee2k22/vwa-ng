#include "client.h"
#include "client_udp.h"
#include "client_udp_stream.h"
#include "common.h"
#include "session.h"

#include <arpa/inet.h>
#include <ev.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <quicly.h>
#include <quicly/defaults.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <stdbool.h>
#include <float.h>
#include <quicly/streambuf.h>
#include <picotls/../../t/util.h>


session_t *ht_quic_to_udp = NULL;
session_t *ht_udp_to_quic = NULL;
extern int client_quic_socket;
extern quicly_conn_t *conn;
extern quicly_context_t client_ctx;
extern const quicly_stream_callbacks_t udp_client_stream_callbacks;

session_t *client_create_udp_session(request_t *req, quicly_stream_t *stream)
{
    session_t *session = (session_t *) malloc(sizeof(session_t));
    assert(session != NULL);

    gettimeofday(&session->start_tm, NULL);
    session->stream = stream;
    session->stream_id = stream->stream_id;
    session->conn = stream->conn;
    session->stream_active = true;

    memcpy(&(session->req), req, sizeof(request_t));

    return session;
}

void process_udp_packet(char *buf, ssize_t len)
{
    struct iphdr *iph = (struct iphdr *) buf;

    if (iph->protocol != IPPROTO_UDP) {
        log_warn("tun device received non UDP packets. \n");
        return;
    }

    struct udphdr *udph = (struct udphdr *)(buf + iph->ihl * 4);
    struct sockaddr_in src, dst;

    src.sin_family = dst.sin_family = AF_INET;
    src.sin_addr.s_addr = iph->saddr;
    src.sin_port = udph->source;

    dst.sin_addr.s_addr = iph->daddr;
    dst.sin_port = udph->dest;

    request_t *req = (request_t *) malloc(sizeof(request_t));
    bzero(req, sizeof(request_t));
    memcpy(&(req->sa), (void *) &src, sizeof(struct sockaddr_in));
    memcpy(&(req->da), (void *) &dst, sizeof(struct sockaddr_in));
    req->protocol = IPPROTO_UDP;

    session_t *session = find_session_u2q(&ht_udp_to_quic, req);

    if (!session) {
        quicly_stream_t *stream = NULL;
        int ret = quicly_open_stream(conn, &stream, 0);
        assert(ret == 0);
        stream->callbacks = &udp_client_stream_callbacks;
        session = client_create_udp_session(req, stream);
        assert(session != NULL);

        add_to_hash_u2q(&ht_udp_to_quic, session);
        add_to_hash_q2u(&ht_quic_to_udp, session);
    }

    assert(session != NULL);
    assert(session->stream != NULL);
    //FIXME in the next version, we may use emit to send the UDP packets.
    // the following line would write the whole packet including IP header
    // into stream
    log_info("writting to quicly streambuf %ld, len: %ld.\n", session->stream->stream_id, len);
    quicly_streambuf_egress_write(session->stream, buf, len);

    if (req)
       free(req);

    return;
}

void client_tun_read_cb(EV_P_ ev_io *w, int revents)
{
    int fd = w->fd;
    ssize_t read_bytes = 0, total_read_bytes = 0;
    char buf[4096];
    bzero(buf, sizeof(buf));

    while ((read_bytes = read(fd, buf, sizeof(buf))) > 0) {
        //process readed packets;
        process_udp_packet(buf, read_bytes);
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

int open_tun_dev(const char *devname)
{
    struct ifreq ifr;
    int fd, err;
    if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
        perror("open /dev/net/tun");
        exit(1);
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, devname, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) == -1) {
        perror("ioctl TUNSETIFF");
        close(fd);
        exit(1);
    }

    return fd;
}

int create_udp_raw_socket(int tun_fd)
{
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (raw_sock < 0) {
        perror("socket(AF_INET, SOCK_RAW)");
        close(tun_fd);
        return 1;
    }

    int on = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(tun_fd);
        close(raw_sock);
        return 1;
    }

    return raw_sock;
}

int run_cpep_udp_server(char *devname)
{
    int fd = open_tun_dev(devname);
    assert(fd > 0);

    ev_io *tun_read_watcher = (ev_io *) malloc(sizeof(ev_io));
    ev_io_init(tun_read_watcher, client_tun_read_cb, fd, EV_READ);
    ev_io_start(EV_DEFAULT, tun_read_watcher);

    ev_run(loop, 0);
    return 0;
}


