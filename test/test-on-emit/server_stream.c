#include "server_stream.h"

#include <ev.h>
#include <stdbool.h>
#include <quicly/streambuf.h>

typedef struct
{
    uint64_t target_offset;
    uint64_t acked_offset;
    quicly_stream_t *stream;
    int report_id;
    int report_second;
    uint64_t report_num_packets_sent;
    uint64_t report_num_packets_lost;
    uint64_t total_num_packets_sent;
    uint64_t total_num_packets_lost;
    ev_timer report_timer;
    char *buf;
} server_stream;

static int report_counter = 0;

static void print_report(server_stream *s)
{
    quicly_stats_t stats;
    quicly_get_stats(s->stream->conn, &stats);
    s->report_num_packets_sent = stats.num_packets.sent - s->total_num_packets_sent;
    s->report_num_packets_lost = stats.num_packets.lost - s->total_num_packets_lost;
    s->total_num_packets_sent = stats.num_packets.sent;
    s->total_num_packets_lost = stats.num_packets.lost;
    printf("connection %i second %i send window: %"PRIu32" packets sent: %"PRIu64" packets lost: %"PRIu64"\n", s->report_id, s->report_second, stats.cc.cwnd, s->report_num_packets_sent, s->report_num_packets_lost);
    fflush(stdout);
    ++s->report_second;
}

static void server_report_cb(EV_P, ev_timer *w, int revents)
{
    print_report((server_stream*)w->data);
}

static void server_stream_destroy(quicly_stream_t *stream, quicly_error_t err)
{
    printf("stream %ld is destroyed.\n", stream->stream_id);
}

static void server_stream_send_shift(quicly_stream_t *stream, size_t delta)
{
    printf("func: %s, line: %d ,", __func__, __LINE__);
    printf("stream: %ld, delta: %ld\n", stream->stream_id, delta);
    server_stream *s = stream->data;
    s->acked_offset += delta;
}

static void server_stream_send_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all)
{
    printf("func: %s, line: %d ,", __func__, __LINE__);
    printf("stream: %ld, off: %ld, dst: %p, len: %ld, wrote_all: %d\n", stream->stream_id, off, dst, (*len), (*wrote_all));
    server_stream *s = stream->data;
    uint64_t data_off = s->acked_offset + off;
    static int count;

    if(data_off + *len < s->target_offset) {
        *wrote_all = 0;
    } else {
        printf("done sending\n");
        *wrote_all = 1;
        *len = s->target_offset - data_off;
        assert(data_off + *len == s->target_offset);
    }
    count += 1;
    char c = '1' + count;
    memset(dst, c, *len);
    printf("func: %s, line: %d ,", __func__, __LINE__);
    printf("stream: %ld, off: %ld, dst: %p, len: %ld, wrote_all: %d\n", stream->stream_id, off, dst, (*len), (*wrote_all));
}

static void server_stream_send_stop(quicly_stream_t *stream, quicly_error_t err)
{
    printf("server_stream_send_stop stream-id=%li\n", stream->stream_id);
    fprintf(stderr, "received STOP_SENDING: %li\n", err);
}

static void server_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    if (len == 0)
        return;

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    printf("stream: %ld, received %ld bytes: \n \"%.*s\"\n", stream->stream_id, input.len, (int ) input.len, (char *) input.base);

    quicly_stream_sync_recvbuf(stream, input.len);

    if(quicly_recvstate_transfer_complete(&stream->recvstate)) {
        printf("request received, sending data\n");
        quicly_stream_sync_sendbuf(stream, 1);
        ev_timer_start(EV_DEFAULT, &((server_stream*)stream->data)->report_timer);
    }
}

static void server_stream_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    printf("server_stream_receive_reset stream-id=%li\n", stream->stream_id);
    fprintf(stderr, "received RESET_STREAM: %li\n", err);
}

static const quicly_stream_callbacks_t server_stream_callbacks = {
    &server_stream_destroy,
    &quicly_streambuf_egress_shift,
    &quicly_streambuf_egress_emit,
    &server_stream_send_stop,
    &server_stream_receive,
    &server_stream_receive_reset
};

quicly_error_t server_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    server_stream *s = malloc(sizeof(server_stream));
    s->target_offset = UINT64_MAX;
    s->acked_offset = 0;
    s->stream = stream;
    s->report_id = report_counter++;
    s->report_second = 0;
    s->report_num_packets_sent = 0;
    s->report_num_packets_lost = 0;
    s->total_num_packets_sent = 0;
    s->total_num_packets_lost = 0;
    ev_timer_init(&s->report_timer, server_report_cb, 1.0, 1.0);
    s->report_timer.data = s;

    int ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t));
    assert(ret == 0);

    stream->callbacks = &server_stream_callbacks;

    return 0;
}
