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

static void server_stream_send_stop(quicly_stream_t *stream, quicly_error_t err)
{
    log_debug("stream %ld received STOP_SENDING: %li\n", stream->stream_id, err);
    clean_up_from_stream(&ht_quic_to_tcp, stream, err);
}

static void inline log_session_peer(quicly_stream_t *stream, int fd, struct sockaddr_in *sa, struct sockaddr_in *da)
{ 
     char temp[256] = {0};
     log_debug("session quic: %ld <-> tcp: %d  (%s) created.\n",
               stream->stream_id, fd, get_conn_str(sa, da, temp, sizeof(temp)));
     return;
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
        log_warn("stream %ld failed to create tcp conn to %s:%d . \n",
                     stream->stream_id, inet_ntoa(da->sin_addr), ntohs(da->sin_port));
        free(ns);
        return NULL;
    }

    assert(fd > 0);
    set_non_blocking(fd);
    ns->fd = fd;

    log_session_peer(stream, fd, sa, da);

    //add session into hashtables
    add_to_hash_t2q(&ht_tcp_to_quic, ns);
    add_to_hash_q2t(&ht_quic_to_tcp, ns);

    //add socket read watcher
    ev_io *socket_read_watcher = (ev_io *)malloc(sizeof(ev_io));
    ev_io_init(socket_read_watcher, server_tcp_read_cb, fd, EV_READ);
    ev_io_start(loop, socket_read_watcher);

    //add socket write watcher, don't start it unless we have EV_BLOCK happens.
    ev_io *socket_write_watcher = (ev_io *)malloc(sizeof(ev_io));
    ev_io_init(socket_write_watcher, tcp_write_cb, fd, EV_WRITE);

    ns->tcp_read_watcher = socket_read_watcher;
    ns->tcp_write_watcher = socket_write_watcher;

    return ns;
};

static void server_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    if (len == 0)
        return;

    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    long int stream_id = stream->stream_id;

    session_t *s = find_session_q2t(&ht_quic_to_tcp, stream_id);

    if (!s) {
        frame_t *ctrl_frame = (frame_t *) (input.base);
        if (ctrl_frame->type != 1) {
            log_debug("stream: %ld received %ld bytes unexpected data.\n", stream_id, len);
            return;
        }

        if (ctrl_frame->s.dst.sin_port == 0) {
            return;
        }

        s = create_session(stream, ctrl_frame);
        if (!s) {
            log_error("stream: %ld could not create session.\n", stream_id);
            close_stream(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
            return;
        }
        s->ctrl_frame_received = true;

        size_t delta = sizeof(frame_t);
        input.base += delta;
        input.len -= delta;
        quicly_stream_sync_recvbuf(stream, delta);
    }

    if (input.len == 0)
        return;

    assert(input.len > 0);

    size_t bytes_sent = -1, total_bytes_sent = 0;
    while ((bytes_sent = write(s->fd, input.base, input.len)) > 0) {
        input.base += bytes_sent;
        input.len -= bytes_sent;
        total_bytes_sent += bytes_sent;
        if (input.len == 0)
             break;
    }

    if (total_bytes_sent > 0) {
        quicly_stream_sync_recvbuf(stream, total_bytes_sent);
#if 0
        if(input.len > 0)
            quicly_streambuf_ingress_shift(stream, total_bytes_sent);
        else
            quicly_stream_sync_recvbuf(stream, total_bytes_sent);
#endif
    }

    if (bytes_sent < 0) {
        if (errno == EAGAIN) {
            /* when stream ingress buf is not empty, and tcp sk is blocking
              start TCP EV_WRITE watcher */
            if (input.len > 0)
                ev_io_start(loop, s->tcp_write_watcher);
         } else
             assert(errno != 0);
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

    if (connect(fd, sa, sizeof(struct sockaddr)) == -1) {
        perror("connect() failed");
        fprintf(stderr,"connect() return %d, %s.\n", errno, strerror(errno));
        return -1;
    }

    log_debug("created tcp %d to connect %s:%d.\n", fd,
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

    return 0;
}

void server_tcp_read_cb(EV_P_ ev_io *w, int revents)
{
    int fd = w->fd;
    session_t *session = find_session_t2q(&ht_tcp_to_quic, fd);

    if (!session) {
        log_warn("could not find session for tcp %d. \n", fd);
        ev_io_stop(loop, w);
        free(w);
        close(fd);
        return;
    }

    quicly_stream_t *stream = quicly_get_stream(session->conn, session->stream_id);
    assert(stream != NULL);

    //TODO need a way to detect egress queue length, only call read
    // if queue_length <= queue_capacity - read buffer size.
    char buf[SOCK_READ_BUF_SIZE] = {0};
    size_t bytes_write_to_quic = 0, read_bytes = 0;
    while ((read_bytes = read(fd, buf, sizeof(buf))) > 0) {
        quicly_streambuf_egress_write(stream, buf, read_bytes);
        bytes_write_to_quic += read_bytes;
    }

    if (read_bytes == 0) {
        log_debug("fd: %d remote peer closed calling clean_up_from_tcp .\n", fd);
        clean_up_from_tcp(&ht_tcp_to_quic, fd);
        return;
    }

    if(read_bytes < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_error("fd: %d, read() failed with %d, \"%s\".\n", fd, errno, strerror(errno));
            clean_up_from_tcp(&ht_tcp_to_quic, fd);
        } else {
            log_debug("fd: %d, read() is blocked with %d, \"%s\".\n", fd, errno, strerror(errno));
        }
    }

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

    static int count;
    count += 1;
    if ((count % 150) == 1) {
        log_info("ctrl stream %ld, recv: %.*s", stream->stream_id, (int) input.len, (char *) input.base);
    }
    /* remove used bytes from receive buffer */
    quicly_stream_sync_recvbuf(stream, input.len);

    const char *msg = "Server received and reply PONG!\n";
    quicly_streambuf_egress_write(stream, msg, strlen(msg));

    return;
}


static void server_stream_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    log_debug("server_stream_receive_reset stream-id=%li, received RESET_STREAM: %li\n",
                                      stream->stream_id, err);
    clean_up_from_stream(&ht_quic_to_tcp, stream, err);
}

static void server_stream_on_destroy(quicly_stream_t *stream, quicly_error_t err)
{
    quicly_streambuf_destroy(stream, err);
    log_debug("stream_id: %ld is destroyed.\n", stream->stream_id);
}

static const quicly_stream_callbacks_t server_stream_callbacks = {
    server_stream_on_destroy,
    quicly_streambuf_egress_shift,
    quicly_streambuf_egress_emit,
    server_stream_send_stop,
    server_stream_receive,
    server_stream_receive_reset
};

static const quicly_stream_callbacks_t server_ctrl_stream_callbacks = {
    server_stream_on_destroy,
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
