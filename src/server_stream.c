#include "server.h"
#include "server_stream.h"
#include "server_udp_stream.h"
#include "common.h"
#include "uthash.h"

#include <ev.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/time.h>
#include <quicly/streambuf.h>

extern ssize_t streambuf_high_watermarker;

extern session_t *ht_tcp_to_quic;
extern session_t *ht_quic_to_flow;

extern struct ev_loop *loop;

int create_tcp_connection(struct sockaddr *sa);
void server_tcp_read_cb(EV_P_ ev_io *w, int revents);
void server_tcp_write_cb(EV_P_ ev_io *w, int revents);

void server_clean_up_init_from_quic(quicly_stream_t *stream, quicly_error_t err)
{
    session_t *s = find_session_q2f(&ht_quic_to_flow, stream);

    if (!s) {
        terminate_quic_stream(stream, err);
        return;
    }

    delete_session_init_from_quic(s, err);

    return;
}

static void server_stream_send_stop(quicly_stream_t *stream, quicly_error_t err)
{
    log_info("stream %ld received STOP_SENDING: %li\n", stream->stream_id, err);
    server_clean_up_init_from_quic(stream, err);
}

session_t *create_tcp_session(quicly_stream_t *stream, request_t *req)
{
    long int stream_id = stream->stream_id;
    session_t *ns = (session_t *) malloc(sizeof(session_t));
    bzero(ns, sizeof(session_t));
    memcpy(&(ns->req), req, sizeof(request_t));

    struct sockaddr_in *da = (struct sockaddr_in *) &(ns->req.da);
    struct sockaddr_in *sa = (struct sockaddr_in *) &(ns->req.sa);
    ns->stream_id = stream_id;
    ns->conn = stream->conn;
    ns->stream = stream;

    int fd = create_tcp_connection((struct sockaddr *) da);
    if (fd < 0) {
        fprintf(stderr, "failed to create tcp for stream: %ld. \n", stream->stream_id);
        free(ns);
        return NULL;
    }

    assert(fd > 0);
    ns->fd = fd;

    ns->stream_active = true;
    ns->tcp_active = true;

    //add session into hashtables
    add_to_hash_t2q(&ht_tcp_to_quic, ns);
    add_to_hash_q2f(&ht_quic_to_flow, ns);

    //add socket read watcher
    ev_io *socket_read_watcher = (ev_io *)malloc(sizeof(ev_io));
    ev_io_init(socket_read_watcher, server_tcp_read_cb, fd, EV_READ);
    ev_io_start(loop, socket_read_watcher);

    //add socket write watcher, BUT don't start it until we have backlog.
    ev_io *socket_write_watcher = (ev_io *)malloc(sizeof(ev_io));
    ev_io_init(socket_write_watcher, server_tcp_write_cb, fd, EV_WRITE);

    ns->tcp_read_watcher = socket_read_watcher;
    ns->tcp_write_watcher = socket_write_watcher;

    return ns;
};


static void server_stream_tcp_receive(session_t *s)
{
    assert(s != NULL);
    quicly_stream_t *stream = s->stream;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0) {
        return;
    }

    if (!s->tcp_active) {
        log_error("stream %ld received data, but remote tcp conn. might be closed.\n",
                           stream->stream_id);
        quicly_stream_sync_recvbuf(stream, input.len);
        return;
    }

    log_debug("stream: %ld recv buff has %ld bytes available.\n", stream->stream_id, input.len);

    ssize_t bytes_sent = -1, total_bytes_sent = 0;

    while ((bytes_sent = write(s->fd, input.base, input.len)) > 0 ) {
        input.base += bytes_sent;
        input.len -= bytes_sent;
        total_bytes_sent += bytes_sent;
        if (input.len == 0)
            break;
    }

    log_debug("stream %ld, total_bytes_sent: %ld, input.len: %ld\n",
                     stream->stream_id, total_bytes_sent, input.len);

    if (total_bytes_sent > 0) {
         if (input.len > 0)
             quicly_streambuf_ingress_shift(stream, total_bytes_sent);
         else
             quicly_stream_sync_recvbuf(stream, total_bytes_sent);
    }

    if (bytes_sent < 0) {
         if (errno == EAGAIN) {
             if (input.len > 0) {
                 if (ev_is_active(s->tcp_write_watcher) != true) {
                     ev_io_start(loop, s->tcp_write_watcher);
                     log_info("stream %ld has %ld bytes in recv buf left, and start ev_writer\n",
                                 stream->stream_id, (ssize_t) input.len);
                 }
             }
         } else {
             log_error("fd %d write failed w/ %d, \"%s\". \n", s->fd, errno, strerror(errno));
             s->tcp_active = false;
             close_tcp_conn(s);
         }
    }

    return;

}

session_t *create_new_session(quicly_stream_t *stream)
{
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    if (input.len < sizeof(request_t)) {
         log_error("stream %ld received %ld bytes which is not ctrl_frame or request.\n",
                        stream->stream_id, input.len);
         return NULL;
    }

    request_t *req = (request_t *) input.base;

    if (req->protocol != IPPROTO_TCP && req->protocol != IPPROTO_UDP) {
         log_error("stream %ld received %ld bytes which is not a valid request (proto: %d).\n",
                        stream->stream_id, input.len, req->protocol);
         return NULL;
    }

    session_t *ns = NULL;

    if (req->protocol == IPPROTO_TCP) {
        ns = create_tcp_session(stream, req);
    } else {
        //req->protocol == IPPROTO_UDP
        ns = create_udp_session(stream, req);
    }

    input.len -= sizeof(request_t);

    log_info("stream %ld, consumed %ld bytes and  %ld bytes in receive buf. \n",
                  stream->stream_id, sizeof(request_t), input.len);

    if (input.len > 0)
        quicly_streambuf_ingress_shift(stream, sizeof(request_t));
    else
        quicly_stream_sync_recvbuf(stream, sizeof(request_t));

    return ns;
}

static void server_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    if (len == 0)
        return;

    log_debug("stream %ld received %ld bytes.\n", stream->stream_id, len);

    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;


    session_t *session = find_session_q2f(&ht_quic_to_flow, stream);
    log_debug("find session %p, created for stream %ld, %p \n", session,  stream->stream_id, stream);

    if (!session) { // might be new session.
        session = create_new_session(stream);
        if (!session) {
            log_warn("stream: %ld received %ld bytes, but could not create a new session.\n",
                         stream->stream_id, len);
            quicly_stream_sync_recvbuf(stream, len);
            return;
        }

        log_debug("session %p created for stream %ld, %p \n", session, stream->stream_id, stream);
    }

    assert(session != NULL);
    gettimeofday(&(session->active_tm), NULL);

    if (session->req.protocol == IPPROTO_TCP) {
        //note, input already in stream's receive buf.
        server_stream_tcp_receive(session);
    } else if (session->req.protocol == IPPROTO_UDP) {
        //for udp flows.  quicly stream carries the whole ip pts incl. iphdr.
        server_stream_udp_receive(session);
    } else {
        //should not reach here.
        log_error("stream %ld session %p has unsported protocol %d.\n",
                   stream->stream_id, session, session->req.protocol);
    }

    return;
}

int create_tcp_connection(struct sockaddr *sa)
{
    int fd;
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket failed");
        fprintf(stderr,"socket() return %d, %s.\n", errno, strerror(errno));
        return -1;
    }

    //need set non blocking before calling connect().
    set_non_blocking(fd);

    int ret = connect(fd, sa, sizeof(struct sockaddr));
    if (ret == -1 && errno != EINPROGRESS) {
        perror("connect() failed");
        fprintf(stderr,"tcp fd %d connect() return %d, %s.\n", fd, errno, strerror(errno));
        return -1;
    }

    printf("created tcp %d to connect %s:%d.\n", fd,
                   inet_ntoa(((struct sockaddr_in *)sa)->sin_addr),
                    ntohs(((struct sockaddr_in *)sa)->sin_port));

    return fd;
}

void server_tcp_write_cb(EV_P_ ev_io *w, int revents)
{
    int fd = w->fd;
    session_t *s = find_session_t2q(&ht_tcp_to_quic, fd);

    if (!s) {
        printf("could not find quic connection for tcp fd: %d.\n", fd);
        ev_clear_pending(loop, w);
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

    ssize_t orig_len = input.len, bytes_sent = -1, total_bytes_sent = 0;
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
            log_error("fd %d write failed w/ %d, \"%s\". \n", fd, errno, strerror(errno));
            close_tcp_conn(s);
        }
    }

    return;
}


void server_tcp_read_cb(EV_P_ ev_io *w, int revents)
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

    ssize_t qlen = estimate_quicly_stream_egress_qlen(stream);
    log_debug("stream: %ld, egress qlen %ld bytes. \n", stream->stream_id, qlen);

    if (qlen > streambuf_high_watermarker) {
         log_debug("stream %ld sndbuf is full (%ld bytes) and don't read from socket %d.\n", stream->stream_id, qlen, fd);
         return;
    }

    char buf[SOCK_READ_BUF_SIZE];
    ssize_t total_read_bytes = 0, read_bytes = 0;

    while ((read_bytes = read(fd, buf, sizeof(buf))) > 0) {
        quicly_streambuf_egress_write(stream, buf, read_bytes);
        total_read_bytes += read_bytes;
        //TODO need refactor this part.
        if (total_read_bytes + qlen > streambuf_high_watermarker)
            break;
    }

    if (read_bytes == 0) {
         // tcp connection has been closed.
        log_info("fd: %d remote peer closed.\n", fd);
        quicly_streambuf_egress_shutdown(stream);
        s->tcp_active = false;
        close_tcp_conn(s);
        return;
    }

    if(read_bytes < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_warn("fd: %d, read() failed with %d, \"%s\".\n", fd, errno, strerror(errno));
            quicly_streambuf_egress_shutdown(stream);
            s->tcp_active = false;
            close_tcp_conn(s);
        } else {
            log_debug("fd: %d, read() is blocked with %d, \"%s\".\n", fd, errno, strerror(errno));
        }
    }
}

static void server_ctrl_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    if (len == 0)
         return;

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    //log_debug("ctrl stream %ld, recv: %.*s\n", stream->stream_id, (int) input.len, (char *) input.base);
    quicly_stream_sync_recvbuf(stream, len);

    const char *msg = "Server received and reply PONG!\n";
    quicly_streambuf_egress_write(stream, msg, strlen(msg));

    return;
}


static void server_stream_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    printf("server_stream_receive_reset stream-id=%li\n", stream->stream_id);
    fprintf(stderr, "received RESET_STREAM: %li\n", err);
}

static const quicly_stream_callbacks_t server_stream_callbacks = {
    quicly_streambuf_destroy,
    quicly_streambuf_egress_shift,
    quicly_streambuf_egress_emit,
    server_stream_send_stop,
    server_stream_receive,
    server_stream_receive_reset
};

static const quicly_stream_callbacks_t server_ctrl_stream_callbacks = {
    quicly_streambuf_destroy,
    quicly_streambuf_egress_shift,
    quicly_streambuf_egress_emit,
    server_stream_send_stop,
    server_ctrl_stream_receive,
    server_stream_receive_reset
};

quicly_error_t server_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{

    int ret;
    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
        return ret;

    if (stream->stream_id == 0)
        stream->callbacks = &server_ctrl_stream_callbacks;
    else
        stream->callbacks = &server_stream_callbacks;

    return 0;
}
