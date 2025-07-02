#include "client.h"
#include "client_stream.h"
#include "common.h"

#include <ev.h>
#include <stdio.h>
#include <quicly.h>
#include <quicly/defaults.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <stdbool.h>
#include <float.h>
#include <quicly/streambuf.h>
#include <sys/time.h>
#include <picotls/../../t/util.h>

static int client_socket = -1;
static quicly_conn_t *conn = NULL;
static ev_timer client_timeout;
quicly_context_t client_ctx;
static quicly_cid_plaintext_t next_cid;
int64_t start_time = 0;
int64_t connect_time = 0;
static bool quit_after_first_byte = false;
static ptls_iovec_t resumption_token;

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
    const char *req = "qperf start sending";

    quicly_streambuf_egress_write(stream, req, strlen(req));
    //quicly_streambuf_egress_shutdown(stream);
}

static void client_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn, quicly_error_t err,
                                 uint64_t frame_type, const char *reason, size_t reason_len)
{
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        fprintf(stderr, "transport close:code=0x%" PRIx16 ";frame=%" PRIu64 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err),
                frame_type, (int)reason_len, reason);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        fprintf(stderr, "application close:code=0x%" PRIx16 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len,
                reason);
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        fprintf(stderr, "stateless reset\n");
    } else {
        fprintf(stderr, "unexpected close:code=%li\n", err);
    }
}

static quicly_stream_open_t stream_open = {&client_on_stream_open};

static quicly_closed_by_remote_t closed_by_remote = {&client_on_conn_close};

int create_tcp_listening_socket(const short port)
{
    int sd;
    struct sockaddr_in addr;

    if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
        perror("socket error");
        return -1;
    }

    set_non_blocking(sd);

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    // Bind socket to address
    if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
        perror("bind error");
    }

    // Start listing on the socket
    if (listen(sd, 2) < 0) {
        perror("listen error");
        return -1;
    }

    fprintf(stdout, "created a TCP server sk %d listening on port %d\n", sd, port);
    return sd;
}

void debug_streambuf_egress_dump_info(quicly_stream_t *stream)
{
    quicly_streambuf_t *sbuf = (quicly_streambuf_t *)stream->data;
    quicly_sendbuf_t *egress = &sbuf->egress;

    printf("stream: %ld, ", stream->stream_id);
    printf("off_in_first_vec: %ld, ", egress->off_in_first_vec);
    printf("bytes_written: %ld, ", egress->bytes_written);
    printf("vecs.size: %ld, ", egress->vecs.size);
    printf("vecs.capacity: %ld, ", egress->vecs.capacity);
    printf("\n");
    for (int i = 0; i < egress->vecs.size; i++) {
         quicly_sendbuf_vec_t entry = egress->vecs.entries[i];
         printf("vecs[%d], len: %ld, cbdata: %p.\n", i, entry.len, entry.cbdata);
    }
    printf("\n");
    fflush(stdout);

}


#define BUFFER_SIZE 4096
void tcp_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{

    char buffer[BUFFER_SIZE];
    ssize_t read_bytes;

    quicly_stream_t *stream = quicly_get_stream(conn, 0);

    assert(stream != NULL);
    // Receive message from client socket
    ssize_t bytes_sent_to_quic = 0;

    //somehow get the egress queue length from quic stream.
    int i = 0;
    while ((read_bytes = read(watcher->fd, buffer, BUFFER_SIZE)) > 0) {
        fprintf(stdout, "read %ld bytes from fd: %d.\n", read_bytes, watcher->fd);

        printf("iter: %d, before write ", i);
        debug_streambuf_egress_dump_info(stream);

        quicly_streambuf_egress_write(stream, buffer, read_bytes);

        printf("iter: %d, after write ", i);
        debug_streambuf_egress_dump_info(stream);
        bytes_sent_to_quic += read_bytes;
        i += 1;
    }

    if (read_bytes == 0) {
        ev_io_stop(loop,watcher);
        close(watcher->fd);
        free(watcher);
        return;
    }

    if (read_bytes < 0 && errno != EAGAIN) {
         ev_io_stop(loop,watcher);
         close(watcher->fd);
         free(watcher);
         return;
    }
    
    printf("calling send_pending\n");
    if(!send_pending(&client_ctx, client_socket, conn)) {
        printf("failed to connect: send_pending failed\n");
        exit(1);
    }

    return;

}


void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_sd;


    // Accept client request
    client_sd = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_sd < 0) {
        perror("accept error");
        return;
    }

    set_non_blocking(client_sd);

    struct ev_io *w_client = (struct ev_io*) malloc (sizeof(struct ev_io));
    ev_io_init(w_client, tcp_read_cb, client_sd, EV_READ);
    ev_io_start(loop, w_client);

    fprintf(stdout, "accepted a new client %d and start tcp_read_cb.\n", client_sd);

    return;
}


int run_client(const char *port, bool gso, const char *logfile, const char *cc, int iw, const char *host, int runtime_s, bool ttfb_only)
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
    client_ctx.initcwnd_packets = iw;

    if(strcmp(cc, "reno") == 0) {
        client_ctx.init_cc = &quicly_cc_reno_init;
    } else if(strcmp(cc, "cubic") == 0) {
        client_ctx.init_cc = &quicly_cc_cubic_init;
    }

    if (gso) {
        enable_gso();
    }

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

    if (logfile)
    {
        setup_log_event(client_ctx.tls, logfile);
    }

    printf("starting client with host %s, port %s, runtime %is, cc %s, iw %i\n", host, port, runtime_s, cc, iw);
    quit_after_first_byte = ttfb_only;

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

    client_set_quit_after(runtime_s);

    int tcp_fd = create_tcp_listening_socket(5203);
    ev_io tcp_accept_watcher;
    ev_io_init(&tcp_accept_watcher, accept_cb, tcp_fd, EV_READ);
    ev_io_start(loop, &tcp_accept_watcher);

    ev_run(loop, 0);
    return 0;
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
