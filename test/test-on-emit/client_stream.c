#include "client_stream.h"
#include "client.h"
#include "common.h"
#include <ev.h>
#include <stdbool.h>
#include <quicly/streambuf.h>
#include <sys/time.h>

static int current_second = 0;
static uint64_t bytes_received = 0;
static ev_timer report_timer;
static bool first_receive = true;
static int runtime_s = 30;


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
    if (first_receive) {
        bytes_received = 0;
        first_receive = false;
        //ev_timer_init(&report_timer, report_cb, 1.0, 1.0);
        //ev_timer_start(ev_default_loop(0), &report_timer);
        //on_first_byte();
    }

    if (len == 0) {
        return;
    }

    extern quicly_context_t client_ctx;
    extern int64_t connect_time, start_time;

    connect_time = client_ctx.now->cb(client_ctx.now);

    printf("func: %s, line: %d, time: %ld ", __func__, __LINE__, connect_time - start_time);
    printf("stream: %ld, off: %ld, src: %p, len: %ld \n", stream->stream_id, off, src, len);

    quicly_error_t ret = 0;

    if ((ret = quicly_streambuf_ingress_receive(stream, off, src, len)) != 0) {
        printf("quicly_streambuf_ingress_receive() returns with %ld. \n", ret);
        return;
    }

    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    printf("input.base: %p, input.len: %ld.\n", input.base, input.len);

    //assume consume first 100 bytes.
    printf("first 10 bytes of input.base: %.*s\n", 10, input.base);
    printf("first 10 bytes of src: %.*s.\n", 10, (char *) src);

    static int i;
    i += 1;
    quicly_streambuf_ingress_shift(stream, input.len - i);
    //quicly_stream_sync_recvbuf(stream, input.len - i);
}

static void client_stream_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    fprintf(stderr, "received RESET_STREAM: %li\n", err);
}

static void client_stream_send_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all) 
{
    print_now(); 
    printf("before calling emit: %lu, off: %lu, dst: %p, size: %lu, wrote_all: %d \n", 
                    stream->stream_id, off, dst, *len, *wrote_all);
 
    quicly_streambuf_egress_emit(stream, off, dst, len, wrote_all);

    print_now();
    printf("after calling emit: %lu, off: %lu, dst: %p, size: %lu, wrote_all: %d \n", 
                    stream->stream_id, off, dst, *len, *wrote_all);

}

static const quicly_stream_callbacks_t client_stream_callbacks = {
    &quicly_streambuf_destroy,
    &quicly_streambuf_egress_shift,
    &client_stream_send_emit,
    &client_stream_send_stop,
    &client_stream_receive,
    &client_stream_receive_reset
};


quicly_error_t client_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    int ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t));
    assert(ret == 0);
    stream->callbacks = &client_stream_callbacks;

    return 0;
}


void client_set_quit_after(int seconds)
{
    runtime_s = seconds;
}
