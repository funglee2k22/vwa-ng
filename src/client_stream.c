#include "client_stream.h"
#include "client.h"
#include "common.h"
#include <ev.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <quicly/streambuf.h>

static int current_second = 0;
static uint64_t bytes_received = 0;
static ev_timer report_timer;
static int runtime_s = 3600;

extern session_t *ht_tcp_to_quic;
extern session_t *ht_quic_to_tcp;


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

    if(current_second >= runtime_s) {
        //quit_client();
    }
}

static void client_stream_send_stop(quicly_stream_t *stream, quicly_error_t err)
{
    fprintf(stderr, "received STOP_SENDING: %li\n", err);
}

static void client_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    if (len == 0)
        return;

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    long int stream_id = stream->stream_id;
    session_t *session = find_session_q2t(&ht_quic_to_tcp, stream_id);

    if (!session) {
        //fprintf(stderr, "stream: %ld remote tcp conn.  might be closed. \n", stream_id);
        return;
    }

    assert(session != NULL);

    //copy stream content into the APP write buffer.
    char *base =session->q2t_buf + session->q2t_read_offset;
    size_t actual_read_len = session->buf_len - session->q2t_read_offset;
    if (len > actual_read_len) {
        memcpy(base, src, actual_read_len);
        session->q2t_read_offset += actual_read_len;
    } else {
        memcpy(base, src, len);
        session->q2t_read_offset += len;
        actual_read_len = len;
    }

    quicly_stream_sync_recvbuf(stream, actual_read_len);

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
    fprintf(stderr, "received RESET_STREAM: %li\n", err);
}

static const quicly_stream_callbacks_t client_stream_callbacks = {
    &quicly_streambuf_destroy,
    &quicly_streambuf_egress_shift,
    &quicly_streambuf_egress_emit,
    &client_stream_send_stop,
    &client_stream_receive,
    &client_stream_receive_reset
};

static const quicly_stream_callbacks_t client_ctrl_stream_callbacks = {
    &quicly_streambuf_destroy,
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
