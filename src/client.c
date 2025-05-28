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

static int client_quic_socket = -1;
static int client_tcp_socket = -1;
static quicly_conn_t *conn = NULL;
static quicly_stream_t *ctrl_stream = NULL;
static ev_timer client_timeout;
static quicly_context_t client_ctx;
static quicly_cid_plaintext_t next_cid;
static int64_t start_time = 0;
static int64_t connect_time = 0;
static ptls_iovec_t resumption_token;



struct ev_loop *loop = NULL;
session_t *ht_quic_to_tcp = NULL;
session_t *ht_tcp_to_quic = NULL;


static void client_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn, quicly_error_t err,
                                 uint64_t frame_type, const char *reason, size_t reason_len);

static quicly_stream_open_t stream_open = {&client_on_stream_open};

static quicly_closed_by_remote_t closed_by_remote = {&client_on_conn_close};

void client_timeout_cb(EV_P_ ev_timer *w, int revents);

//void enqueue_request(quicly_conn_t *conn);

void client_refresh_timeout()
{
    int64_t timeout = clamp_int64(quicly_get_first_timeout(conn) - client_ctx.now->cb(client_ctx.now),
                                  1, 200);
    client_timeout.repeat = timeout / 1000.;
    ev_timer_again(EV_DEFAULT, &client_timeout);
}

void client_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    static int count;

    count++;
    if ((count % 10) == 0) {
         printf("timeout_cb count %d\n", count);
    }

    if(!send_pending(&client_ctx, client_quic_socket, conn)) {
        my_debug();
        fprintf(stderr, "quicly conn is close-able, but keep it open\n");
        //quicly_free(conn);
        //exit(0);
    }
    client_refresh_timeout();
}

void client_quic_read_cb(EV_P_ ev_io *w, int revents)
{
    // retrieve data
    uint8_t buf[4096];
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    quicly_decoded_packet_t packet;
    ssize_t bytes_received;
    static ssize_t quic_total_received, quic_output_thresh;

    while ((bytes_received = recvfrom(w->fd, buf, sizeof(buf), MSG_DONTWAIT,(struct sockaddr *) &sa, &salen)) != -1) {

        quic_total_received += bytes_received;
        if (quic_total_received >= quic_output_thresh) {
            printf("quic-udp total received %ld bytes.\n", quic_total_received);
            quic_output_thresh += 1024 * 1024 * 10;
        }

        for (size_t offset = 0; offset < bytes_received; ) {
            size_t packet_len = quicly_decode_packet(&client_ctx, &packet, buf, bytes_received, &offset);
            if (packet_len == SIZE_MAX) {
                break;
            }

            // handle packet --------------------------------------------------
            int ret = quicly_receive(conn, NULL, (struct sockaddr *) &sa, &packet);
            if (ret != 0 && ret != QUICLY_ERROR_PACKET_IGNORED) {
                fprintf(stderr, "quicly_receive returned %i\n", ret);
                exit(1);
            }

            // check if connection ready --------------------------------------
            if (connect_time == 0 && quicly_connection_is_ready(conn)) {
                connect_time = client_ctx.now->cb(client_ctx.now);
                int64_t establish_time = connect_time - start_time;
                fprintf(stdout, "connection establishment time: %lums\n", establish_time);
            }
        }
    }

    if (errno != EWOULDBLOCK && errno != 0) {
        perror("recvfrom failed");
    }

    if(!send_pending(&client_ctx, client_quic_socket, conn)) {
        my_debug();
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

    ctrl_stream = stream;

    quicly_streambuf_egress_write(stream, req, strlen(req));
    //quicly_streambuf_egress_shutdown(stream);
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
    if(conn == NULL)
        return;

    quicly_close(conn, 0, "");

    if(!send_pending(&client_ctx, client_quic_socket, conn)) {
        printf("send_pending failed during connection close");
        quicly_free(conn);
        exit(0);
    }
    client_refresh_timeout();
}

static inline int clt_tcp_to_quic(int fd, void *buf, int len)
{
    session_t *s = find_session_t2q(&ht_tcp_to_quic, fd);
    assert(s != NULL);

    if (!s) {
        printf("could not find session for tcp %d\n", fd);
        return -1;
    }

    long int sid = s->stream_id;
    assert(sid > 0);

    quicly_stream_t *stream = quicly_get_stream(conn, sid);
    assert(stream != NULL);

    quicly_streambuf_egress_write(stream, buf, len);
    //quicly_streambuf_egress_shutdown(stream);
    //printf("write %d bytes to stream %ld egress buf.\n", len, stream->stream_id);

    return 0;

}

void client_cleanup(int fd)
{
    session_t *s = find_session_t2q(&ht_tcp_to_quic, fd);

    if (s) {
        delete_session(&ht_tcp_to_quic, &ht_quic_to_tcp, s);
        quicly_stream_t *stream = quicly_get_stream(conn, s->stream_id);
        assert(stream != NULL);
        quicly_streambuf_egress_shutdown(stream);
    }

    free(s);
    close(fd);
    return;
}

void client_tcp_read_cb(EV_P_ ev_io *w, int revents)
{
    char buf[4096];
    int fd = w->fd;
    ssize_t read_bytes = 0;
    static ssize_t total_read_bytes, clt_tcp_output_thresh;

    while ((read_bytes = read(fd, buf, sizeof(buf))) > 0) {
        total_read_bytes += read_bytes;
        int ret = clt_tcp_to_quic(fd, buf, read_bytes);
        if (ret != 0) {
            printf("fd: %d failed to write into quic stream.\n", fd);
            return;
        }
    }

    if (total_read_bytes >= clt_tcp_output_thresh) {
        printf("clt tcp fd: %d, total read %ld bytes.\n", fd, total_read_bytes);
        clt_tcp_output_thresh += 1024 * 10;
    }

    if (read_bytes == 0) {
         // tcp connection has been closed.
        printf("fd: %d remote peer closed.\n", fd);
        ev_io_stop(loop, w);
        client_cleanup(fd);
        free(w);
    } else if (read_bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
        //Nothing to read.
        //printf("fd: %d noththing to read.\n");
        } else {
            printf("fd: %d, read() failed with %d, \"%s\".\n", fd, errno, strerror(errno));
            ev_io_stop(loop, w);
            client_cleanup(fd);
            free(w);
        }
    }

    client_refresh_timeout();
    return;
}

void client_tcp_accept_cb(EV_P_ ev_io *w, int revents)
{
    int fd = -1;
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);

    fd = accept(w->fd, (struct sockaddr *)&sa, &salen);
    if (fd < 0) {
        perror("accept(2) failed.");
        return;
    }

    set_non_blocking(fd);

    struct sockaddr_in da;
    socklen_t dalen = sizeof(da);

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &da, &dalen) != 0) {
        perror("getsockopt(SO_ORIGINAL_DST) failed");
        return;
    }

    printf("Accepted client %s:%d -> %s:%d on fd %d\n",
           inet_ntoa(sa.sin_addr), ntohs(sa.sin_port),
                   inet_ntoa(da.sin_addr), ntohs(da.sin_port),
           fd);

    //open quicly stream;
    quicly_stream_t *stream = NULL;
    int ret = quicly_open_stream(conn, &stream, 0);
    assert(ret == 0);

    long int stream_id = stream->stream_id;
    session_t *session = (session_t *)malloc(sizeof(session_t));
    session->fd = fd;
    session->stream_id = stream->stream_id;
    session->conn = stream->conn;
    memcpy(&(session->sa), (void *)&sa, salen);
    memcpy(&(session->da), (void *)&da, dalen);

    add_to_hash_t2q(&ht_tcp_to_quic, session);
    add_to_hash_q2t(&ht_quic_to_tcp, session);

    frame_t ctrl_frame;
    ctrl_frame.type = 1;
    memcpy(&(ctrl_frame.s.src), &sa,  sizeof(sa));
    memcpy(&(ctrl_frame.s.dst), &da,  sizeof(da));

    //send clt side session info to server;
    quicly_streambuf_egress_write(stream, (void *) &ctrl_frame, sizeof(frame_t));


    ev_io *client_tcp_socket_watcher = (ev_io *)malloc(sizeof(ev_io));
    ev_io_init(client_tcp_socket_watcher, client_tcp_read_cb, fd, EV_READ);
    ev_io_start(loop, client_tcp_socket_watcher);

    client_refresh_timeout();

    return;
}


int clt_setup_tcp_listener(const char *host, const char *port)
{
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);

    int fd = -1;
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket(2) failed.");
        exit(-1);
    }

    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &(int){1}, sizeof(int)) != 0) {
        perror("setsockopt(IP_TRANSPARENT) failed.");
        return -1;
    }

    memset(&sa, 0, salen);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(atoi(port));
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (void *)&sa, sizeof(sa)) != 0) {
        perror("bind(2) failed.");
        return -1;
    }

    if (listen(fd, 128) != 0) {
        perror("listen(2) failed.");
        return -1;
    }

    return fd;
}

int clt_setup_quic_connection(const char *host, const char *port)
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

    struct sockaddr_storage sas;
    socklen_t salen;
    if (resolve_address((void *)&sas, &salen, host, port, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP) != 0) {
        exit(-1);
    }

    struct sockaddr *sa = (struct sockaddr *)&sas;

    client_quic_socket = socket(sa->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (client_quic_socket == -1) {
        perror("socket(2) failed");
        return -1;
    }

    if (sa->sa_family == AF_INET) {
        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = INADDR_ANY;
        local.sin_port = 0; // Let the OS choose the port
        if (bind(client_quic_socket, (struct sockaddr *)&local, sizeof(local)) != 0) {
            perror("bind(2) failed");
            return -1;
        }
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 local;
        memset(&local, 0, sizeof(local));
        local.sin6_family = AF_INET6;
        local.sin6_addr = in6addr_any;
        local.sin6_port = 0; // Let the OS choose the port
        if (bind(client_quic_socket, (struct sockaddr *)&local, sizeof(local)) != 0) {
            perror("bind(2) failed");
            return -1;
        }
    } else {
        fprintf(stderr, "Unknown address family\n");
        return -1;
    }

    printf("starting pep client with remote host %s, port %s\n", host, port);

    // start time
    start_time = client_ctx.now->cb(client_ctx.now);
    int ret = quicly_connect(&conn, &client_ctx, host, sa, NULL, &next_cid, resumption_token, NULL, NULL, NULL);
    assert(ret == 0);
    ++next_cid.master_id;

    enqueue_request(conn);
    if(!send_pending(&client_ctx, client_quic_socket, conn)) {
        printf("failed to connect: send_pending failed\n");
        exit(-1);
    }

    if(conn == NULL) {
        fprintf(stderr, "quic connection == NULL\n");
        exit(-1);
    }

    return client_quic_socket;
}

void sigpipe_handler(int signo)
{
    if (signo == SIGPIPE) {
        fprintf(stderr, "SIGPIPE(%d) received. errno: %d, \"%s\"\n", signo, errno, strerror(errno));
        return;
    }
    return;
}


int main(int argc, char** argv)
{
    int port = 4433;
    int tcp_port = 8443;
    const char *host = "192.168.30.1";
    const char *logfile = NULL;
    const char *local_host = "127.0.0.1";

    loop = EV_DEFAULT;

    char port_char[16];
    snprintf(port_char, sizeof(port_char), "%d", port);
    client_quic_socket = clt_setup_quic_connection(host, port_char);

    snprintf(port_char, sizeof(port_char), "%d", tcp_port);
    client_tcp_socket = clt_setup_tcp_listener(local_host, port_char);

    //TODO: it is a quick fix, for some reason, SIGPIPE was not handled
    //correctly.
    //signal(SIGPIPE, SIG_IGN);
    if (signal(SIGPIPE, sigpipe_handler) == SIG_ERR) {
        perror("can't catch SIGPIPE");
        exit(-1);
    }

    set_non_blocking(client_tcp_socket);
    set_non_blocking(client_quic_socket);

    ev_io quic_socket_watcher, tcp_socket_accept_watcher;
    ev_io_init(&quic_socket_watcher, &client_quic_read_cb, client_quic_socket, EV_READ);
    ev_io_start(loop, &quic_socket_watcher);

    ev_io_init(&tcp_socket_accept_watcher, &client_tcp_accept_cb, client_tcp_socket, EV_READ);
    ev_io_start(loop, &tcp_socket_accept_watcher);

    ev_init(&client_timeout, &client_timeout_cb);
    client_refresh_timeout();

    //int runtime_s = 3600;
    //client_set_quit_after(runtime_s);

    ev_run(loop, 0);

}
