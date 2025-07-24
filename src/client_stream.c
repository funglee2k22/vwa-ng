#include "client.h"
#include "client_stream.h"
#include "client_udp_stream.h"
#include "common.h"
#include <ev.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <quicly/streambuf.h>

static int current_second = 0;
static uint64_t bytes_received = 0;
static ev_timer report_timer;
static int runtime_s = 3600;

extern session_t *ht_tcp_to_quic;
extern session_t *ht_quic_to_flow;


void format_size(char *dst, double bytes)
{
    bytes *= 8;
    const char *suffixes[] = {"bit/s", "kbit/s", "mbit/s", "gbit/s"};
    int i = 0;
    while(i < 4 && bytes > 1024) {
        bytes /= 1024;
        i++;
    }
    sprintf(dst, "%.4g %s", bytes, suffixes[i]);
}

static void report_cb(EV_P_ ev_timer *w, int revents)
{
    char size_str[100];
    format_size(size_str, bytes_received);

    printf("second %i: %s (%lu bytes received)\n", current_second, size_str, bytes_received);
    fflush(stdout);
    ++current_second;
    bytes_received = 0;
}

void client_clean_up_init_from_quic(quicly_stream_t *stream, quicly_error_t err)
{
    log_debug("client clean session initiated from stream: %ld with %li.\n", stream->stream_id, err);

    session_t *s = find_session_q2f(&ht_quic_to_flow, stream);

    if (!s) {
        terminate_quic_stream(stream, err);
        return;
    }

    delete_session_init_from_quic(s, err);

}

static void client_stream_send_stop(quicly_stream_t *stream, quicly_error_t err)
{
    log_info("stream %ld received STOP_SENDING: %li\n", stream->stream_id, err);
    client_clean_up_init_from_quic(stream, err);
}


static void client_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    long int stream_id = stream->stream_id;

    if (len == 0)
        return;

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    session_t *s = find_session_q2f(&ht_quic_to_flow, stream);
    if (!s || !s->tcp_active) {
        log_error("stream %ld received %ld bytes, but remote tcp conn. might be closed.\n", stream_id, len);
        quicly_stream_sync_recvbuf(stream, len);
        return;
    }

    if (s && !s->first_read_quic) {
        s->first_read_quic = true;
        print_session_event(s, "func: %s, line: %d, event: first_read_quic.\n", __func__, __LINE__);
    }



    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0) {
        //log_warn("stream %ld quicly_streambuf_ingress_get return input.len: %ld bytes.\n",
        //                stream->stream_id, input.len);
        return;
    }
    ssize_t orig_len = input.len;

    log_debug("stream: %ld recv buff has %ld bytes available.\n", stream->stream_id, input.len);

    ssize_t bytes_sent = -1, total_bytes_sent = 0;
    while ((bytes_sent = write(s->fd, input.base, input.len)) > 0 ) {
        input.base += bytes_sent;
        input.len -= bytes_sent;
        total_bytes_sent += bytes_sent;
        if (input.len == 0)
            break;
    }

    log_debug("stream %ld, off: %ld, len: %ld, total_bytes_sent: %ld, input.len: %ld\n",
                     stream->stream_id, off, len, total_bytes_sent, input.len);

    assert(total_bytes_sent <= orig_len);

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
             delete_session_init_from_tcp(s, errno);
         }
    }
    return;
}

static void client_ctrl_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    if (len == 0) return;
    //log_debug("ctrl stream receive %zu bytes.\n", len);
    //client side ctrl stream handling.
    quicly_stream_sync_recvbuf(stream, len);

    return;
}

static void client_stream_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    log_info("stream %ld, received RESET_STREAM: %li\n", stream->stream_id, err);
    //FIXME do we need to terminate session here ?
}

static void client_stream_on_destroy(quicly_stream_t *stream, quicly_error_t err)
{
    log_info("stream %ld is destroyed w/ error %ld.\n", stream->stream_id, err);
    quicly_streambuf_destroy(stream, err);
    return;
}

static const quicly_stream_callbacks_t client_stream_callbacks = {
    &client_stream_on_destroy,
    &quicly_streambuf_egress_shift,
    &quicly_streambuf_egress_emit,
    &client_stream_send_stop,
    &client_stream_receive,
    &client_stream_receive_reset
};

static const quicly_stream_callbacks_t client_ctrl_stream_callbacks = {
    &client_stream_on_destroy,
    &quicly_streambuf_egress_shift,
    &quicly_streambuf_egress_emit,
    &client_stream_send_stop,
    &client_ctrl_stream_receive,
    &client_stream_receive_reset
};

quicly_error_t client_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    int ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t));
    assert(ret == 0);

    if (stream->stream_id == 0)
        stream->callbacks = &client_ctrl_stream_callbacks;
    else
        stream->callbacks = &client_stream_callbacks;

    return 0;
}

void client_set_quit_after(int seconds)
{
    runtime_s = seconds;
}
