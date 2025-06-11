#include "server.h"
#include "server_stream.h"
#include "common.h"
#include "uthash.h"

#include <ev.h>
#include <errno.h>
#include <stdbool.h>
#include <quicly/streambuf.h>

extern session_t *ht_tcp_to_quic;
extern session_t *ht_quic_to_tcp;

extern struct ev_loop *loop;

int create_tcp_connection(struct sockaddr *sa);
void server_tcp_read_cb(EV_P_ ev_io *w, int revents);
void server_tcp_write_cb(EV_P_ ev_io *w, int revents);

#define USE_EV_EVENT_FEED

static void server_stream_send_stop(quicly_stream_t *stream, quicly_error_t err)
{
    log_info("stream %ld received STOP_SENDING: %li\n", stream->stream_id, err);
    clean_up_from_stream(&ht_quic_to_tcp, stream, err);
}

session_t *create_session(quicly_stream_t *stream, frame_t *ctrl_frame)
{
    long int stream_id = stream->stream_id;
    session_t *ns = (session_t *) malloc(sizeof(session_t));
    bzero(ns, sizeof(session_t));
    memcpy(&(ns->da), &(ctrl_frame->s.dst), sizeof(struct sockaddr_in));
    memcpy(&(ns->sa), &(ctrl_frame->s.src), sizeof(struct sockaddr_in));

    struct sockaddr_in *da = (struct sockaddr_in *) &(ns->da);
    struct sockaddr_in *sa = (struct sockaddr_in *) &(ns->sa);
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
    set_non_blocking(fd);
    ns->fd = fd;
    fprintf(stdout, "session quic: %ld <-> tcp: %d  (%s:%d -> %s:%d created.\n",
            stream->stream_id, fd,
            inet_ntoa(sa->sin_addr), ntohs(sa->sin_port),
            inet_ntoa(da->sin_addr), ntohs(da->sin_port));

    ns->t2q_buf = malloc(APP_BUF_SIZE);
    ns->q2t_buf = malloc(APP_BUF_SIZE);
    assert(ns->t2q_buf != NULL);
    assert(ns->q2t_buf != NULL);
    ns->buf_len = APP_BUF_SIZE;
    ns->t2q_read_offset = ns->t2q_write_offset = 0;
    ns->q2t_read_offset = ns->q2t_write_offset = 0;

    //add session into hashtables
    add_to_hash_t2q(&ht_tcp_to_quic, ns);
    add_to_hash_q2t(&ht_quic_to_tcp, ns);

    //add socket read watcher
    ev_io *socket_read_watcher = (ev_io *)malloc(sizeof(ev_io));
    ev_io_init(socket_read_watcher, server_tcp_read_cb, fd, EV_READ);
    ev_io_start(loop, socket_read_watcher);

    //add socket write watcher
    ev_io *socket_write_watcher = (ev_io *)malloc(sizeof(ev_io));
    ev_io_init(socket_write_watcher, server_tcp_write_cb, fd, EV_WRITE);
#ifndef USE_EV_EVENT_FEED
    ev_io_start(loop, socket_write_watcher);
#endif

    ns->tcp_read_watcher = socket_read_watcher;
    ns->tcp_write_watcher = socket_write_watcher;

    return ns;
};

static void server_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    //log_debug("stream: %ld, received %ld bytes.\n", stream->stream_id, len);

    if (len == 0)
        return;

    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    //FIXME  strange... need double check
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    size_t l = input.len;
    char *base = input.base;
    long int stream_id = stream->stream_id;

    session_t *s = find_session_q2t(&ht_quic_to_tcp, stream_id);

    if (!s) {
        frame_t *ctrl_frame = (frame_t *) base;
        if (ctrl_frame->type != 1) {
            //fprintf(stderr, "stream: %ld received %ld bytes unexpected data.\n", stream_id, len);
            return;
        }
        s = create_session(stream, ctrl_frame);
        if (!s) {
            fprintf(stderr, "stream: %ld could not create session.\n", stream_id);
            return;
        }
        s->ctrl_frame_received = true;
        base += sizeof(frame_t);
        l -= sizeof(frame_t);
        quicly_stream_sync_recvbuf(stream, sizeof(frame_t));
    }

    if (l <= 0)
        return;

    char *dst = s->q2t_buf + s->q2t_read_offset;
    size_t actual_read_len = s->buf_len - s->q2t_read_offset;

    if (l > actual_read_len) {
        memcpy(dst, base, actual_read_len);
        s->q2t_read_offset += actual_read_len;
    } else {
        memcpy(dst, base, l);
        s->q2t_read_offset += l;
        actual_read_len = l;
    }

    quicly_stream_sync_recvbuf(stream, actual_read_len);
#ifdef USE_EV_EVENT_FEED
    ev_feed_event(loop, s->tcp_write_watcher, EV_WRITE);
#endif
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

    if (connect(fd, sa, sizeof(struct sockaddr)) == -1) {
        perror("connect() failed");
        fprintf(stderr,"connect() return %d, %s.\n", errno, strerror(errno));
        return -1;
    }

    printf("created tcp %d to connect %s:%d.\n", fd,
                   inet_ntoa(((struct sockaddr_in *)sa)->sin_addr),
                    ntohs(((struct sockaddr_in *)sa)->sin_port));

    return fd;
}

int srv_tcp_to_quic(int fd, char *buf, int len)
{
    session_t *s = find_session_t2q(&ht_quic_to_tcp, fd);

    if (!s) {
        printf("could not find quic stream peer for tcp %d.\n", fd);
        return -1;
    }

    long int stream_id = s->stream_id;
    quicly_conn_t *conn = s->conn;
    quicly_stream_t *stream = quicly_get_stream(conn, stream_id);

    if (!stream) {
        printf("failed to get stream %ld for tcp %d.\n", stream_id, fd);
        return -1;
    }

    quicly_streambuf_egress_write(stream, buf, len);
    //quicly_streambuf_egress_shutdown(stream);

    return 0;
}

void server_tcp_write_cb(EV_P_ ev_io *w, int revents)
{
   int fd = w->fd;
    session_t *session = find_session_t2q(&ht_tcp_to_quic, fd);

    if (!session) {
        printf("could not find quic connection for tcp fd: %d.\n", fd);
        ev_io_stop(loop, w);
        free(w);
        close(fd);
        return;
    }

    ssize_t len = session->q2t_read_offset - session->q2t_write_offset;
    if (len <= 0) { // nothing to sent;
        session->q2t_read_offset = session->q2t_write_offset = 0;
        return;
    }

    ssize_t bytes_sent = -1;
    char *base = session->q2t_buf + session->q2t_write_offset;

    while ((bytes_sent = write(fd, base, len)) > 0) {
        session->q2t_write_offset += bytes_sent;
        base += bytes_sent;
        len -= bytes_sent;
        if (len == 0)
            break;
    }

    if (bytes_sent == -1) {
       if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "tcp %d write is blocked with error %d, %s\n", fd, errno, strerror(errno));
        } else {
            fprintf(stderr, "tcp %d write error %d, %s\n", fd, errno, strerror(errno));
            clean_up_from_tcp(&ht_tcp_to_quic, fd);
            return;
        }
    }

    return;
}


static inline int write_to_quic_stream_egress_buf(session_t *s)
{
    assert(s != NULL);
    long int sid = s->stream_id;
    assert(sid > 0);

    quicly_stream_t *stream = quicly_get_stream(s->conn, sid);
    assert(stream != NULL);

    char *buf = s->t2q_buf + s->t2q_write_offset;
    size_t len = s->t2q_read_offset - s->t2q_write_offset;

    assert(len > 0);

    int ret = quicly_streambuf_egress_write(stream, buf, len);

    if (ret != 0) {
        fprintf(stderr, "quic stream %ld failed to write into egress buf %d.\n", sid, ret);
        return -1;
    }

    s->t2q_write_offset = s->t2q_read_offset = 0;

    return 0;
}

void server_tcp_read_cb(EV_P_ ev_io *w, int revents)
{
    int fd = w->fd;
    session_t *session = find_session_t2q(&ht_tcp_to_quic, fd);

    if (!session) {
        fprintf(stderr, "could not find session for tcp %d. \n", fd);
        ev_io_stop(loop, w);
        free(w);
        close(fd);
        return;
    }

    char *base = session->t2q_buf + session->t2q_read_offset;
    size_t available_len = session->buf_len - session->t2q_read_offset;
    ssize_t read_bytes = 0;

    while ((read_bytes = read(fd, base, available_len)) > 0) {
        session->t2q_read_offset += read_bytes;
        int ret = write_to_quic_stream_egress_buf(session);
        if (ret != 0) {
            printf("fd: %d failed to write into quic stream.\n", fd);
            return;
        }
        base = session->t2q_buf + session->t2q_read_offset;
        available_len = session->buf_len - session->t2q_read_offset;
    }

    if (read_bytes == 0) {
         // tcp connection has been closed.
        log_debug("fd: %d remote peer closed.\n", fd);
    } else {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            //Nothing to read.
            //printf("fd: %d noththing to read errno: %d, %s.\n", fd, errno, strerror(errno));
            return;
        } else {
            log_warn("fd: %d, read() failed with %d, \"%s\".\n", fd, errno, strerror(errno));
        }
    }

    clean_up_from_tcp(&ht_tcp_to_quic, fd);
    return;

}

static void server_ctrl_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    if (len == 0)
         return;

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    quicly_stream_sync_recvbuf(stream, len);

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);

    log_debug("ctrl stream %ld, recv: %.*s\n", stream->stream_id, (int) input.len, (char *) input.base);
    const char *msg = "Server received and reply PONG!\n";
    quicly_streambuf_egress_write(stream, msg, strlen(msg));

    return;
}


static void server_stream_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    printf("server_stream_receive_reset stream-id=%li\n", stream->stream_id);
    fprintf(stderr, "received RESET_STREAM: %li\n", err);
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
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
