#include "client.h"
#include "client_stream.h"
#include "common.h"
#include <ev.h>

#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <quicly.h>
#include <quicly/defaults.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <stdbool.h>
#include <float.h>
#include <quicly/streambuf.h>
#include <picotls/../../t/util.h>

static int client_socket = -1;
static quicly_conn_t *conn = NULL;
static ev_timer client_timeout;
static quicly_context_t client_ctx;
static quicly_cid_plaintext_t next_cid;
static int64_t start_time = 0;
static int64_t connect_time = 0;
static bool quit_after_first_byte = false;
static ptls_iovec_t resumption_token;

static void client_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn, quicly_error_t err,
                                 uint64_t frame_type, const char *reason, size_t reason_len);

static quicly_stream_open_t stream_open = {&client_on_stream_open};

static quicly_closed_by_remote_t closed_by_remote = {&client_on_conn_close};

void client_timeout_cb(EV_P_ ev_timer *w, int revents);

void client_refresh_timeout()
{
    int64_t timeout = clamp_int64(quicly_get_first_timeout(conn) - client_ctx.now->cb(client_ctx.now),
                                  1, 200);
    client_timeout.repeat = timeout / 1000.;
    ev_timer_again(EV_DEFAULT, &client_timeout);
}

void client_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    if(!send_pending(&client_ctx, client_socket, conn)) {
        quicly_free(conn);
        exit(0);
    }

    client_refresh_timeout();
}

void client_read_cb(EV_P_ ev_io *w, int revents)
{
    // retrieve data
    uint8_t buf[4096];
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    quicly_decoded_packet_t packet;
    ssize_t bytes_received;

    while((bytes_received = recvfrom(w->fd, buf, sizeof(buf), MSG_DONTWAIT,(struct sockaddr *) &sa, &salen)) != -1) {
        for(size_t offset = 0; offset < bytes_received; ) {
            size_t packet_len = quicly_decode_packet(&client_ctx, &packet, buf, bytes_received, &offset);
            if(packet_len == SIZE_MAX) {
                break;
            }

            // handle packet --------------------------------------------------
            int ret = quicly_receive(conn, NULL, (struct sockaddr *) &sa, &packet);
            if(ret != 0 && ret != QUICLY_ERROR_PACKET_IGNORED) {
                fprintf(stderr, "quicly_receive returned %i\n", ret);
                exit(1);
            }

            // check if connection ready --------------------------------------
            if(connect_time == 0 && quicly_connection_is_ready(conn)) {
                connect_time = client_ctx.now->cb(client_ctx.now);
                int64_t establish_time = connect_time - start_time;
                printf("connection establishment time: %lums\n", establish_time);
            }
        }
    }

    if(errno != EWOULDBLOCK && errno != 0) {
        perror("recvfrom failed");
    }

    if(!send_pending(&client_ctx, client_socket, conn)) {
        quicly_free(conn);
        exit(0);
    }

    client_refresh_timeout();
}

void enqueue_request(quicly_conn_t *conn)
{
    quicly_stream_t *stream;
    int ret = quicly_open_stream(conn, &stream, 0);
    assert(ret == 0);
    const char *req = "quic-pep client start a connection";
    
    quicly_streambuf_egress_write(stream, req, strlen(req));
    quicly_streambuf_egress_shutdown(stream);
}

static void client_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn, quicly_error_t err,
                                 uint64_t frame_type, const char *reason, size_t reason_len)
{
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        fprintf(stderr, "transport close:code=0x%lx ;frame=%" PRIu64 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err),
                frame_type, (int)reason_len, reason);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        fprintf(stderr, "application close:code=0x%lx ;reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len,
                reason);
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        fprintf(stderr, "stateless reset\n");
    } else {
        fprintf(stderr, "unexpected close:code=%li\n", err);
    }
}

void quit_client()
{
    if(conn == NULL) {
        return;
    }

    quicly_close(conn, 0, "");
    if(!send_pending(&client_ctx, client_socket, conn)) {
        printf("send_pending failed during connection close");
        quicly_free(conn);
        exit(0);
    }
    client_refresh_timeout();
}

void on_first_byte()
{
    printf("time to first byte: %lums\n", client_ctx.now->cb(client_ctx.now) - start_time);
    if(quit_after_first_byte) {
        quit_client();
    }
}

int clt_setup_quic_connection(const char *host, const char *port, const char *logfile) 
{
    setup_session_cache(get_tlsctx());
    quicly_amend_ptls_context(get_tlsctx());

    client_ctx = quicly_spec_context;
    client_ctx.tls = get_tlsctx();
    client_ctx.stream_open = &stream_open;
    client_ctx.closed_by_remote = &closed_by_remote;
    client_ctx.transport_params.max_stream_data.uni = UINT32_MAX;
    client_ctx.transport_params.max_stream_data.bidi_local = UINT32_MAX;
    client_ctx.transport_params.max_stream_data.bidi_remote = UINT32_MAX;
    client_ctx.initcwnd_packets = 20;
    client_ctx.init_cc = &quicly_cc_cubic_init;

    struct ev_loop *loop = EV_DEFAULT;

    struct sockaddr_storage sas;
    socklen_t salen;
    if (resolve_address((void *)&sas, &salen, host, port, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP) != 0) {
        exit(-1);
    }
    
    struct sockaddr *sa = (struct sockaddr *)&sas;
    
    client_socket = socket(sa->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (client_socket == -1) {
        perror("socket(2) failed");
        return 1;
    }
    
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = INADDR_ANY;
        local.sin_port = 0; // Let the OS choose the port
        if (bind(client_socket, (struct sockaddr *)&local, sizeof(local)) != 0) {
            perror("bind(2) failed");
            return 1;
        }
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 local;
        memset(&local, 0, sizeof(local));
        local.sin6_family = AF_INET6;
        local.sin6_addr = in6addr_any;
        local.sin6_port = 0; // Let the OS choose the port
        if (bind(client_socket, (struct sockaddr *)&local, sizeof(local)) != 0) {
            perror("bind(2) failed");
            return 1;
        }
    } else {
        fprintf(stderr, "Unknown address family\n");
        return 1;
    }

    printf("starting pep client with host %s, port %s\n", host, port);

    // start time
    start_time = client_ctx.now->cb(client_ctx.now);

    int ret = quicly_connect(&conn, &client_ctx, host, sa, NULL, &next_cid, resumption_token, NULL, NULL, NULL);
    assert(ret == 0);
    ++next_cid.master_id;

    enqueue_request(conn);
    if(!send_pending(&client_ctx, client_socket, conn)) {
        printf("failed to connect: send_pending failed\n");
        exit(1);
    }

    if(conn == NULL) {
        fprintf(stderr, "connection == NULL\n");
        exit(1);
    }

    ev_io socket_watcher;
    ev_io_init(&socket_watcher, &client_read_cb, client_socket, EV_READ);
    ev_io_start(loop, &socket_watcher);

    ev_init(&client_timeout, &client_timeout_cb);
    client_refresh_timeout();

    int runtime_s = 3600;
    client_set_quit_after(runtime_s);

    ev_run(loop, 0);
    return 0;
}


int main(int argc, char** argv)
{
    int port = 8443;
    const char *host = "192.168.30.1";
    const char *logfile = NULL;

    char port_char[16];
    snprintf(port_char, sizeof(port_char), "%d", port);

    clt_setup_quic_connection(host, port_char, logfile);


}
