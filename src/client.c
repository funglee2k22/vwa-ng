#include "client.h"
#include "client_udp.h"
#include "client_stream.h"
#include "common.h"
#include "session.h"
#include <ev.h>

#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <quicly.h>
#include <quicly/defaults.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <stdbool.h>
#include <float.h>
#include <quicly/streambuf.h>
#include <picotls/../../t/util.h>

static int client_quic_socket = -1;
static int client_udp_tun_fd = -1;
int client_udp_raw_fd = -1;
static int client_tcp_socket = -1;
quicly_conn_t *conn = NULL;
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

void send_heartbeat(quicly_conn_t *conn);

void client_refresh_timeout()
{
    int64_t timeout = clamp_int64(quicly_get_first_timeout(conn) - client_ctx.now->cb(client_ctx.now),
                                  1, 200);
    client_timeout.repeat = timeout / 1000.;
    ev_timer_again(EV_DEFAULT, &client_timeout);
}

void client_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    send_heartbeat(conn);
    if(!send_pending(&client_ctx, client_quic_socket, conn)) {
        log_warn("quicly conn is close-able, but keep it open\n");
    }

    client_refresh_timeout();
}

void client_quic_write_cb(EV_P_ ev_io *w, int revents)
{
    int fd = w->fd;

    if(!send_pending(&client_ctx, fd, conn)) {
        log_warn("quicly conn is close-able, but keep it open\n");
    }

    return;
}
void client_quic_read_cb(EV_P_ ev_io *w, int revents)
{
    // retrieve data
    uint8_t buf[4096];
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    quicly_decoded_packet_t packet;
    ssize_t bytes_received;

    while ((bytes_received = recvfrom(w->fd, buf, sizeof(buf), MSG_DONTWAIT,(struct sockaddr *) &sa, &salen)) != -1) {

        for (size_t offset = 0; offset < bytes_received; ) {
            size_t packet_len = quicly_decode_packet(&client_ctx, &packet, buf, bytes_received, &offset);
            if (packet_len == SIZE_MAX) {
                break;
            }

            // handle packet --------------------------------------------------
            int ret = quicly_receive(conn, NULL, (struct sockaddr *) &sa, &packet);
            if (ret != 0 && ret != QUICLY_ERROR_PACKET_IGNORED) {
                log_error("quicly_receive returned %i\n", ret);
                exit(1);
            }

            // check if connection ready --------------------------------------
            if (connect_time == 0 && quicly_connection_is_ready(conn)) {
                connect_time = client_ctx.now->cb(client_ctx.now);
                int64_t establish_time = connect_time - start_time;
                log_info("connection establishment time: %lums\n", establish_time);
            }
        }
    }

    if (errno != EWOULDBLOCK && errno != 0) {
        perror("recvfrom failed");
    }

    return;
}

void send_heartbeat(quicly_conn_t *conn)
{
    quicly_stream_t *stream = quicly_get_stream(conn, 0);

    if (!stream) {
        quicly_open_stream(conn, &stream, 0);
    }
    assert(stream != NULL);

    const char *msg = "client is alive... say Ping\n";
    int ret = quicly_streambuf_egress_write(stream, msg, strlen(msg));

    if (ret != 0) {
        log_warn("quic stream %ld failed to send heart beat message w/ error  %d.\n", stream->stream_id , ret);
    }

    return;
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

void client_tcp_write_cb(EV_P_ ev_io *w, int revents)
{
    int fd = w->fd;
    session_t *s = find_session_t2q(&ht_tcp_to_quic, fd);

    if (!s) {
        log_warn("could not find quic connection for tcp fd: %d.\n", fd);
        ev_io_stop(loop, w);
        free(w);
        close(fd);
        return;
    }

    assert(s->stream_id != 0);
    quicly_stream_t *stream = quicly_get_stream(s->conn, s->stream_id);
    assert(stream != NULL);

    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0) {
        ev_clear_pending(loop, w);
        ev_io_stop(loop, w);
        return;
    }
    ssize_t orig_len = input.len;
    ssize_t bytes_sent = -1, total_bytes_sent = 0;
    while ((bytes_sent = write(fd, input.base, input.len)) > 0) {
        input.base += bytes_sent;
        input.len -= bytes_sent;
        total_bytes_sent += bytes_sent;
        if (input.len == 0)
            break;
    }

    assert(total_bytes_sent <= orig_len);

    if (total_bytes_sent > 0) {
        assert((ssize_t) input.len >= 0);
        if (input.len > 0)
            quicly_streambuf_ingress_shift(stream, total_bytes_sent);
        else {
            quicly_stream_sync_recvbuf(stream, total_bytes_sent);
            ev_clear_pending(loop, w);
            ev_io_stop(loop, w);
        }
    }

    if (bytes_sent < 0) {
         if (errno == EAGAIN) {
             if (input.len > 0) {
                 log_info("stream %ld has %ld bytes in recv buf left, and wait next EV_WRITE\n",
                                 stream->stream_id, (ssize_t) input.len);
             } else {
                 ev_clear_pending(loop, w);
                 ev_io_stop(loop, w);
             }
         } else {
             log_error("fd %d write failed w/ %d, \"%s\". \n", s->fd, errno, strerror(errno));
             ev_clear_pending(loop, w);
             ev_io_stop(loop, w);
             s->tcp_active = false;
             close_tcp_conn(s);
         }
    }

    return;
}


void client_tcp_read_cb(EV_P_ ev_io *w, int revents)
{

    int fd = w->fd;
    session_t *s = find_session_t2q(&ht_tcp_to_quic, fd);
    if (!s) {
        log_info("could not find session for tcp %d. \n", fd);
        ev_io_stop(loop, w);
        free(w);
        close(fd);
        return;
    }

    quicly_stream_t *stream = s->stream;
    assert(stream != NULL);

    if (!s->first_read_tcp) {
        s->first_read_tcp = true;
        print_session_event(s, "host: client, func: %s, line: %d, event: read_from_tcp.\n", __func__, __LINE__);
    }

    //TODO need a way to detect egress queue length, only call read
    // if queue_length <= queue_capacity - read buffer size.
    char buf[SOCK_READ_BUF_SIZE];
    ssize_t total_read_bytes = 0, read_bytes = 0;

    while ((read_bytes = read(fd, buf, sizeof(buf))) > 0) {
        quicly_streambuf_egress_write(stream, buf, read_bytes);
        total_read_bytes += read_bytes;
    }

    if (read_bytes == 0) {
         // tcp connection has been closed.
        log_info("fd: %d remote peer closed.\n", fd);
        quicly_streambuf_egress_shutdown(stream);
        s->tcp_active = false;
        delete_session_init_from_tcp(s, 0);
        return;
    }

    if(read_bytes < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_warn("fd: %d, read() failed with %d, \"%s\".\n", fd, errno, strerror(errno));
            quicly_streambuf_egress_shutdown(stream);
            s->tcp_active = false;
            delete_session_init_from_tcp(s, errno);
        } else {
            log_debug("fd: %d, read() is blocked with %d, \"%s\".\n", fd, errno, strerror(errno));
        }
    }

    return;
}


session_t *client_create_session(int fd, quicly_stream_t *stream)
{
    long int stream_id = stream->stream_id;
    session_t *session = (session_t *)malloc(sizeof(session_t));

    assert(session != NULL);
    session->fd = fd;
    session->stream_id = stream->stream_id;
    session->conn = stream->conn;
    session->stream = stream;
    session->stream_active = true;
    session->tcp_active = true;

    return session;
}

void client_send_meta_data(quicly_stream_t *stream, request_t *req)
{
    log_debug("stream %ld send meta data (len %ld)  to server.\n",
                  stream->stream_id, sizeof(request_t));

    quicly_streambuf_egress_write(stream, (void *) req, sizeof(request_t));

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

    if (getsockname(fd, (struct sockaddr *)&da, &dalen) != 0) {
        perror("getsockname(2) failed.");
        return;
    }

    char str1[1024], str2[1024];
    snprintf(str1, sizeof(str1), "%s:%d", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
    snprintf(str2, sizeof(str2), "%s:%d", inet_ntoa(da.sin_addr), ntohs(da.sin_port));
    log_info("conn: %s -> %s, fd: %d, event: accept.\n", str1, str2, fd);

    //open quicly stream;
    quicly_stream_t *stream = NULL;
    int ret = quicly_open_stream(conn, &stream, 0);
    assert(ret == 0);

    session_t *session = client_create_session(fd, stream);
    memcpy(&(session->req.sa), (void *)&sa, salen);
    memcpy(&(session->req.da), (void *)&da, dalen);
    session->req.protocol = IPPROTO_TCP;

    add_to_hash_t2q(&ht_tcp_to_quic, session);
    add_to_hash_q2t(&ht_quic_to_tcp, session);

    gettimeofday(&session->start_tm, NULL);
    print_session_event(session, "func: %s, line: %d, event: session_created.\n", __func__, __LINE__);

    client_send_meta_data(stream, &(session->req));

    //preparing ev watchers
    ev_io *client_tcp_read_watcher = (ev_io *)malloc(sizeof(ev_io));
    ev_io_init(client_tcp_read_watcher, client_tcp_read_cb, fd, EV_READ);
    ev_io_start(loop, client_tcp_read_watcher);

    ev_io *client_tcp_write_watcher = (ev_io *)malloc(sizeof(ev_io));
    ev_io_init(client_tcp_write_watcher, client_tcp_write_cb, fd, EV_WRITE);

    session->tcp_read_watcher = client_tcp_read_watcher;
    session->tcp_write_watcher = client_tcp_write_watcher;

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
    client_ctx.transport_params.max_streams_bidi = 4096;
    client_ctx.transport_params.max_streams_uni = 4096;
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

    send_heartbeat(conn);
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
    const char *host = "192.168.10.1";
    const char *logfile = NULL;
    const char *local_host = "127.0.0.1";
    const char *devname = "tun0";

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

    client_udp_tun_fd = open_tun_dev(devname);
    assert(client_udp_tun_fd > 0);

    client_udp_raw_fd = create_udp_raw_socket(client_udp_tun_fd);
    assert(client_udp_raw_fd > 0);

    //setting all socket in non-blocking mode.
    set_non_blocking(client_tcp_socket);
    set_non_blocking(client_quic_socket);
    set_non_blocking(client_udp_tun_fd);
    set_non_blocking(client_udp_raw_fd);

    ev_io udp_read_watcher;
    ev_io_init(&udp_read_watcher, &client_quic_read_cb, client_quic_socket, EV_READ);
    ev_io_start(loop, &udp_read_watcher);

    ev_io tcp_socket_accept_watcher;
    ev_io_init(&tcp_socket_accept_watcher, &client_tcp_accept_cb, client_tcp_socket, EV_READ);
    ev_io_start(loop, &tcp_socket_accept_watcher);

    ev_io tun_read_watcher;
    ev_io_init(&tun_read_watcher, client_tun_read_cb, client_udp_tun_fd, EV_READ);
    ev_io_start(loop, &tun_read_watcher);

    ev_timer_init(&client_timeout, &client_timeout_cb, 0.1, 0.0);
    ev_timer_start(EV_DEFAULT, &client_timeout);

    ev_run(loop, 0);

}

