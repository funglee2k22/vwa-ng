﻿#include "server.h"
#include "server_stream.h"
#include "server_udp.h"
#include "server_udp_stream.h"
#include "common.h"

#include <stdio.h>
#include <ev.h>
#include <quicly.h>
#include <quicly/defaults.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdbool.h>

#include <quicly/streambuf.h>

#include <picotls/openssl.h>
#include <picotls/../../t/util.h>

quicly_conn_t **conns;
int udp_server_socket = -1;

int server_udp_tun_fd = -1;
int server_udp_raw_fd = -1;

static quicly_context_t server_ctx;
static size_t num_conns = 0;
static ev_timer server_timeout;
static quicly_cid_plaintext_t next_cid;
struct ev_loop *loop = NULL;

session_t *ht_tcp_to_quic = NULL;
session_t *ht_udp_to_quic = NULL;
session_t *ht_quic_to_flow = NULL;  //both udp and tcp session are in this hashtab, and quicly_stream_t * is hash key.

static int udp_listen(struct addrinfo *addr)
{
    for (const struct addrinfo *rp = addr; rp != NULL; rp = rp->ai_next) {
        int s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == -1) {
            continue;
        }

        int off = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &off, sizeof(off)) != 0) {
            close(s);
            perror("setsockopt(SO_REUSEADDR) disable failed");
            return -1;
        }

        if(bind(s, rp->ai_addr, rp->ai_addrlen) == 0) {
            return s; // success
        }

        // fail -> close socket and try with next addr
        close(s);
    }

    return -1;
}

static inline quicly_conn_t *find_conn(struct sockaddr_storage *sa, socklen_t salen, quicly_decoded_packet_t *packet)
{
    for(size_t i = 0; i < num_conns; ++i) {
        if(quicly_is_destination(conns[i], NULL, (struct sockaddr *) sa, packet)) {
            return conns[i];
        }
    }
    return NULL;
}

static void append_conn(quicly_conn_t *conn)
{
    ++num_conns;
    conns = realloc(conns, sizeof(quicly_conn_t*) * num_conns);
    assert(conns != NULL);
    conns[num_conns - 1] = conn;

    *quicly_get_data(conn) = calloc(1, sizeof(int64_t));
}

static size_t remove_conn(size_t i)
{
    free(*quicly_get_data(conns[i]));
    quicly_free(conns[i]);
    memmove(conns + i, conns + i + 1, (num_conns - i - 1) * sizeof(quicly_conn_t*));
    --num_conns;

    if (i > 0) {
        return i - 1;
    }
    return 0;
}

static void server_timeout_cb(EV_P_ ev_timer *w, int revents);

void server_send_pending()
{
    int64_t next_timeout = INT64_MAX;
    for (size_t i = 0; i < num_conns; ++i) {
        if (!send_pending(&server_ctx, udp_server_socket, conns[i])) {
            i = remove_conn(i);
        } else {
            next_timeout = min_int64(quicly_get_first_timeout(conns[i]), next_timeout);
        }
    }

    int64_t now = server_ctx.now->cb(server_ctx.now);
    int64_t timeout = clamp_int64(next_timeout - now, 1, 200);
    server_timeout.repeat = timeout / 1000.;
    ev_timer_again(EV_DEFAULT, &server_timeout);
}

static void server_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    server_send_pending();

    remove_inactive_udp_sessions();
}

static inline void server_handle_packet(quicly_decoded_packet_t *packet, struct sockaddr_storage *sa, socklen_t salen)
{
    quicly_conn_t *conn = find_conn(sa, salen, packet);
    if (conn == NULL) {
        // new conn
        int ret = quicly_accept(&conn, &server_ctx, 0, (struct sockaddr *) sa, packet, NULL, &next_cid, NULL, NULL);
        if (ret != 0) {
            printf("quicly_accept failed with code %i\n", ret);
            return;
        }
        ++next_cid.master_id;
        printf("got new connection\n");
        append_conn(conn);
    } else {
        int ret = quicly_receive(conn, NULL, (struct sockaddr *) sa, packet);
        if (ret != 0 && ret != QUICLY_ERROR_PACKET_IGNORED) {
            fprintf(stderr, "quicly_receive returned %i\n", ret);
            exit(1);
        }
    }
}

void server_udp_write_cb(EV_P_ ev_io *w, int revents)
{
    int fd = w->fd;
    for (size_t i = 0; i < num_conns; ++i) {
        if (!send_pending(&server_ctx, fd, conns[i])) {
            //TODO for debug purpose, we close the long idle quicly conn
            i = remove_conn(i);
        }
    }
    return;
}

static void server_udp_read_cb(EV_P_ ev_io *w, int revents)
{
    // retrieve data
    uint8_t buf[4096];
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    quicly_decoded_packet_t packet;
    ssize_t bytes_received;

    while ((bytes_received = recvfrom(w->fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&sa, &salen)) != -1) {
        for (size_t offset = 0; offset < bytes_received; ) {
            size_t packet_len = quicly_decode_packet(&server_ctx, &packet, buf, bytes_received, &offset);
            if (packet_len == SIZE_MAX) {
                break;
            }
            server_handle_packet(&packet, &sa, salen);
        }
    }

    if (errno != EWOULDBLOCK && errno != 0) {
        perror("recvfrom failed");
        fprintf(stderr, "udp sk %d recvfrom() returns with errno %d, %s.\n", w->fd, errno, strerror(errno));
    }

    server_send_pending();
}

static void server_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn, quicly_error_t err,
                                 uint64_t frame_type, const char *reason, size_t reason_len)
{
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        fprintf(stderr, "transport close:code=0x%lx;frame=%" PRIu64 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err),
                frame_type, (int)reason_len, reason);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        fprintf(stderr, "application close:code=0x%lx;reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len,
                reason);
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        fprintf(stderr, "stateless reset\n");
    } else {
        fprintf(stderr, "unexpected close:code=%ld\n", err);
    }
}

static quicly_stream_open_t stream_open = {&server_on_stream_open};
static quicly_closed_by_remote_t closed_by_remote = {&server_on_conn_close};

int srv_setup_quic_listener(const char* address, const char *port, const char *key, const char *cert)
{
    setup_session_cache(get_tlsctx());
    quicly_amend_ptls_context(get_tlsctx());

    server_ctx = quicly_spec_context;
    server_ctx.tls = get_tlsctx();
    server_ctx.stream_open = &stream_open;
    server_ctx.closed_by_remote = &closed_by_remote;
    server_ctx.transport_params.max_streams_bidi = 4096;
    server_ctx.transport_params.max_streams_uni = 4096;
    server_ctx.transport_params.max_stream_data.uni = UINT32_MAX;
    server_ctx.transport_params.max_stream_data.bidi_local = UINT32_MAX;
    server_ctx.transport_params.max_stream_data.bidi_remote = UINT32_MAX;

    load_certificate_chain(server_ctx.tls, cert);
    load_private_key(server_ctx.tls, key);

    struct addrinfo *addr = get_address(address, port);
    if (addr == NULL) {
        fprintf(stderr, "failed get addrinfo for addr %s port %s\n", address, port);
        return -1;
    }

    int server_socket = udp_listen(addr);
    freeaddrinfo(addr);

    if (server_socket == -1) {
        fprintf(stderr, "failed to listen on addr %s port %s\n", address, port);
        return -1;
    }

    fprintf(stdout, "starting server with pid %" PRIu64 ", address %s, port %s\n", get_current_pid(), address, port);

    return server_socket;
}


int main(int argc, char** argv)
{
    int port = 4433;
    const char *address = "192.168.10.1";
    const char *logfile = NULL;
    const char *keyfile = "server.key";
    const char *certfile = "server.crt";
    const char *tun_dev = "tun0";

    char port_char[16];
    snprintf(port_char, sizeof(port_char), "%d", port);

    udp_server_socket = srv_setup_quic_listener(address, port_char, keyfile, certfile);
    assert(udp_server_socket > 0);

    //raw socket only used to send UDP packets to remote ISP servers.
    server_udp_tun_fd = open_tun_dev(tun_dev);
    assert(server_udp_tun_fd > 0);

    server_udp_raw_fd = create_udp_raw_socket(server_udp_tun_fd);
    log_info("raw udp sock %d created.\n", server_udp_raw_fd);
    assert(server_udp_raw_fd > 0);

    set_non_blocking(udp_server_socket);
    set_non_blocking(server_udp_raw_fd);
    set_non_blocking(server_udp_tun_fd);

    signal(SIGPIPE, SIG_IGN);
    loop = EV_DEFAULT;

    ev_io udp_read_watcher;
    ev_io_init(&udp_read_watcher, &server_udp_read_cb, udp_server_socket, EV_READ);
    ev_io_start(loop, &udp_read_watcher);

    ev_io udp_tun_reader;
    ev_io_init(&udp_tun_reader, &server_tun_read_cb, server_udp_tun_fd, EV_READ);
    ev_io_start(loop, &udp_tun_reader);

    ev_timer_init(&server_timeout, &server_timeout_cb, 2., 0.0);
    ev_timer_start(EV_DEFAULT, &server_timeout);

    ev_run(loop, 0);

}
