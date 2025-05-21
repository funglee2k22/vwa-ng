#include "server.h"
#include "server_stream.h"
#include "common.h"
#include "uthash.h"

#include <ev.h>
#include <errno.h>
#include <stdbool.h>
#include <quicly/streambuf.h>

//extern session_t *hh_tcp_to_quic;
//extern session_t *hh_quic_to_tcp;
extern struct ev_loop *loop;

int create_tcp_connection(struct sockaddr *sa);
void server_tcp_read_cb(EV_P_ ev_io *w, int revents);


static void server_stream_send_stop(quicly_stream_t *stream, quicly_error_t err)
{
    printf("%s stream-id=%li\n", __func__, stream->stream_id);
    fprintf(stderr, "received STOP_SENDING: %li\n", err);
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}



// tcp-side error happens, or closed.
// clean up
void server_cleanup_tcp_side(int fd)
{
    session_t *s = hash_find_by_tcp_fd(fd);

    if (s)
        hash_del(s);

    if (fd)
        close(fd);

    if (s && s->conn) {
        long int stream_id = s->stream_id;
        quicly_stream_t *stream = quicly_get_stream(s->conn, stream_id);
        if (stream) {
            quicly_streambuf_egress_shutdown(stream);
            //quicly_streambuf_destroy(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
            //free(stream);
        }
    }

    if (s)
        free(s);
    return;
}


session_t *handle_ctrl_frame(quicly_stream_t *stream, frame_t *ctrl_frame)
{
    long int stream_id = stream->stream_id;
    session_t *p = (session_t *) malloc(sizeof(session_t));
    bzero(p, sizeof(*p));
    memcpy(p, &(ctrl_frame->s), sizeof(session_t));

    struct sockaddr_in *da = (struct sockaddr_in *) &(p->da);
    struct sockaddr_in *sa = (struct sockaddr_in *) &(p->sa);
    p->stream_id = stream_id;
    p->conn = stream->conn;

    int fd = create_tcp_connection((struct sockaddr *) da);
    if (fd < 0) {
        fprintf(stderr, "failed to create tcp for stream: %ld. \n", stream->stream_id);
    free(p);
        return NULL;
    }

    assert(fd > 0);
    set_non_blocking(fd);
    p->fd = fd;
    fprintf(stdout, "session quic: %ld <-> tcp: %d created.\n", stream->stream_id, fd);

    //add session into hashtables
    hash_insert(p);

    //add socket read watcher
    ev_io *socket_watcher = (ev_io *)malloc(sizeof(ev_io));
    ev_io_init(socket_watcher, server_tcp_read_cb, fd, EV_READ);
    ev_io_start(loop, socket_watcher);

    return p;
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
    quicly_stream_sync_recvbuf(stream, len);

    size_t l = input.len;
    char *base = input.base;
    long int stream_id = stream->stream_id;

    session_t *s = hash_find_by_stream_id(stream_id);

    if (!s) {
        frame_t *ctrl_frame = (frame_t *) base;
        if (ctrl_frame->type != 1) {
            //fprintf(stderr, "stream: %ld received %ld bytes unexpected data.\n", stream_id, len);
            return;
        }
        s = handle_ctrl_frame(stream, ctrl_frame);
        assert(s != NULL);
        s->ctrl_frame_received = true;
        base += sizeof(frame_t);
        l -= sizeof(frame_t);
    }

    if (l <= 0)
        return;

    ssize_t send_bytes = send(s->fd, base, l, 0);
    if (send_bytes == -1) {
        perror("send (2) failed.");
        fprintf(stderr, "relay msg from quic to tcp failed with %d, %s.\n", errno, strerror(errno));
        return;
    }

    printf("stream_id: %ld -> tcp: %d, sent %ld bytes.\n", stream_id, s->fd, send_bytes);

    return;

#if 0
    if(quicly_recvstate_transfer_complete(&stream->recvstate)) {
        printf("request received, sending data\n");
        quicly_stream_sync_sendbuf(stream, 1);
    }

    if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        fprintf(stderr, "stream: %ld recv completed, sending data\n", stream->stream_id);
        quicly_stream_sync_sendbuf(stream, 1);
    }
#endif

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
    session_t *s = hash_find_by_tcp_fd(fd);

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


void server_tcp_read_cb(EV_P_ ev_io *w, int revents)
{
    char buf[4096];
    int fd = w->fd, buflen = sizeof(buf);
    ssize_t read_bytes = 0;
    static ssize_t total_size, tcp_output_thresh;

    while ((read_bytes = read(fd, buf, buflen)) > 0) {
        total_size += read_bytes;
        int ret = srv_tcp_to_quic(fd, buf, read_bytes);
        if (ret != 0) {
            printf("fd: %d failed to write into quic stream.\n", fd);
        return;
        }
    }

    if (total_size > tcp_output_thresh) {
        fprintf(stdout, "fd %d total read %ld bytes.\n", fd, total_size);
        tcp_output_thresh += 10 * 1024 * 1024;
    }

    if (read_bytes == 0) {
         // tcp connection has been closed.
        fprintf(stderr, "fd: %d remote peer closed.\n", fd);
        ev_io_stop(loop, w);
        server_cleanup_tcp_side(fd);
        free(w);
    } else {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
        //Nothing to read.
        //printf("fd: %d noththing to read errno: %d, %s.\n", fd, errno, strerror(errno));
        } else {
            printf("fd: %d, read() failed with %d, \"%s\".\n", fd, errno, strerror(errno));
            ev_io_stop(loop, w);
            server_cleanup_tcp_side(fd);
            free(w);
        }
    }

    return;

}

static void server_ctrl_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    if (len == 0) return;

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    quicly_stream_sync_recvbuf(stream, len);

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);

    //printf("ctrl stream %ld, recv: %.*s\n", stream->stream_id, (int) input.len, (char *) input.base);

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
