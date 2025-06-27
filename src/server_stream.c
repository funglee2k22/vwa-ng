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

void server_clean_up_init_from_quic(quicly_stream_t *stream, quicly_error_t err)
{
    session_t *s = find_session_q2t(&ht_quic_to_tcp, stream->stream_id);

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
    ns->fd = fd;

    ns->stream_active = true;
    ns->tcp_active = true;

    //add session into hashtables
    add_to_hash_t2q(&ht_tcp_to_quic, ns);
    add_to_hash_q2t(&ht_quic_to_tcp, ns);

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

session_t *server_process_ctrl_frame(quicly_stream_t *stream)
{
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    if (input.len < sizeof(frame_t)) {
        log_warn("stream %ld, recv data %ld bytes not enough to create session_t (%ld bytes).\n",
                       stream->stream_id, input.len, sizeof(frame_t));
        return NULL;
    }

    frame_t *ctrl_frame = (frame_t *) input.base;
    if (ctrl_frame->type != 1) {
         log_warn("stream: %ld received %ld bytes unexpected data.\n", stream->stream_id, input.len);
         return NULL;
    }

    session_t *s = create_session(stream, ctrl_frame);
    if (!s) {
        log_warn("stream: %ld could not create session.\n", stream->stream_id);
        return NULL;
    }

    s->tcp_active = s->stream_active = s->ctrl_frame_received = true;

    char str_src[128], str_dst[128];
    snprintf(str_src, sizeof(str_src), "%s:%d", inet_ntoa(s->sa.sin_addr), ntohs(s->sa.sin_port));
    snprintf(str_dst, sizeof(str_dst), "%s:%d", inet_ntoa(s->da.sin_addr), ntohs(s->da.sin_port));

    log_info("session quic: %ld <-> tcp: %d  (%s -> %s) created.\n",
            s->stream_id, s->fd, str_src, str_dst);

    if (input.len - sizeof(frame_t) > 0)
        quicly_streambuf_ingress_shift(stream, sizeof(frame_t));
    else
        quicly_stream_sync_recvbuf(stream, sizeof(frame_t));

    return s;

}

static void server_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    if (len == 0)
        return;

    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    long int stream_id = stream->stream_id;
    session_t *s = find_session_q2t(&ht_quic_to_tcp, stream_id);

    if (!s) {
        //it might be a new session.
        s = server_process_ctrl_frame(stream);
        if (!s) {
            log_warn("stream: %ld received %ld bytes, but could not create a new session.\n",
                         stream->stream_id, len);
            quicly_stream_sync_recvbuf(stream, len);
            return;
        }
    }

    assert(s != NULL);

    if (!s->tcp_active) {
        log_error("stream %ld received %ld bytes, but remote tcp conn. might be closed.\n", stream_id, len);
        quicly_stream_sync_recvbuf(stream, len);
        return;
    }

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0) {
        //log_warn("stream %ld quicly_streambuf_ingress_get return input.len: %ld bytes.\n",
        //                stream->stream_id, input.len);
        return;
    }
    log_debug("stream: %ld recv buff has %ld bytes available.\n", stream->stream_id, input.len);

    ssize_t bytes_sent = -1, total_bytes_sent = 0;
    log_debug("stream %ld, off: %ld, len: %ld, total_bytes_sent: %ld, input.len: %ld\n",
                     stream->stream_id, off, len, total_bytes_sent, input.len);

    while ((bytes_sent = write(s->fd, input.base, input.len)) > 0 ) {
        input.base += bytes_sent;
        input.len -= bytes_sent;
        total_bytes_sent += bytes_sent;
        if (input.len == 0)
            break;
    }

    log_debug("stream %ld, off: %ld, len: %ld, total_bytes_sent: %ld, input.len: %ld\n",
                     stream->stream_id, off, len, total_bytes_sent, input.len);

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
