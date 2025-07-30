#include "session.h"
#include "uthash.h"
#include "common.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

extern session_t *ht_tcp_to_quic, \
                 *ht_udp_to_quic, \
                 *ht_quic_to_flow;

const int udp_inactive_thresh_secs = 60;

void dump_request(request_t *r)
{
    printf("req: src: %s:%d, ", inet_ntoa(r->sa.sin_addr), ntohs(r->sa.sin_port));
    printf("dst: %s:%d, ", inet_ntoa(r->da.sin_addr), ntohs(r->da.sin_port));
    printf("protocol: %d, \n", r->protocol);
    return;
}

void add_to_hash_t2q(session_t **hh, session_t *s)
{
     session_t *t = NULL;
     int fd = s->fd;

     HASH_FIND(hh_t2q, *hh, &fd, sizeof(fd), t);

     if (t == NULL) {
        HASH_ADD(hh_t2q, *hh, fd, sizeof(fd), s);
     } else {
        HASH_REPLACE(hh_t2q, *hh, fd, sizeof(fd), s, t);
     }

     return;
}

session_t *find_session_t2q(session_t **hh, int fd)
{
    session_t *r = NULL;

    HASH_FIND(hh_t2q, *hh, &fd, sizeof(fd), r);

    return r;
}

void add_to_hash_q2f(session_t **hh, session_t *s)
{
     session_t *t = NULL;
     quicly_stream_t *stream = s->stream;
     long int stream_id = stream->stream_id;
     s->stream_id = stream_id;

     HASH_FIND(hh_q2f, *hh, &stream_id, sizeof(stream_id), t);
     if (t == NULL) {
        HASH_ADD(hh_q2f, *hh, stream_id, sizeof(stream_id), s);
     } else {
        HASH_REPLACE(hh_q2f, *hh, stream_id, sizeof(stream_id), s, t);
     }
     return;
}

session_t *find_session_q2f(session_t **hh, quicly_stream_t *stream)
{
    session_t *r = NULL;
    long int stream_id = stream->stream_id;

    HASH_FIND(hh_q2f, *hh, &stream_id, sizeof(stream_id), r);

    return r;
}


void delete_session_from_t2q(session_t **t2q, session_t *s)
{
    if (!s || !t2q)
        return;

    HASH_DELETE(hh_t2q, *t2q, s);

    return;
}

void delete_session_from_q2t(session_t **q2t, session_t *s)
{
    if (!s || !q2t)
        return;

    HASH_DELETE(hh_q2f, *q2t, s);

    return;
}

/*
 * adding <udp five tuples, quicly_stream *> into hash table,
 * key is the five tuples.
 */
void add_to_hash_u2q(session_t **hh, session_t *s)
{
    session_t *r = NULL;

    HASH_FIND(hh_u2q, *hh, &(s->req), sizeof(request_t), r);

    if (!r) {
        HASH_ADD(hh_u2q, *hh, req, sizeof(request_t), s);
    } else {
        HASH_REPLACE(hh_u2q, *hh, req, sizeof(request_t), s, r);
    }

    return;
}

session_t *find_session_u2q(session_t **hh, request_t *k)
{
    session_t *r = NULL;

    HASH_FIND(hh_u2q, *hh, k, sizeof(request_t), r);

    return r;
}

void delete_session_u2q(session_t **hh, session_t *s)
{
    if (!s || !hh)
        return;

    HASH_DELETE(hh_u2q, *hh, s);

    return;
}


void delete_session_q2f(session_t **hh, session_t *s)
{
    if (!s || !hh)
        return;

    HASH_DELETE(hh_q2f, *hh, s);

    return;
}


void free_ev_watcher(ev_io *w)
{
    assert(w != NULL);
    if (ev_is_active(w)) {
        ev_clear_pending(loop, w);
        ev_io_stop(loop, w);
    }
    free(w);
    return;
}

void close_tcp_conn(session_t *s)
{
    assert(s!= NULL && s->fd != 0);

    if (s->tcp_read_watcher) {
        free_ev_watcher(s->tcp_read_watcher);
    }

    if (s->tcp_write_watcher) {
        free_ev_watcher(s->tcp_write_watcher);
    }

    s->tcp_active = false;
    close(s->fd);
    return;

}


void terminate_quic_stream(quicly_stream_t *stream, quicly_error_t err)
{
    assert(stream != NULL);

    if (!quicly_sendstate_transfer_complete(&(stream->sendstate)))
        quicly_reset_stream(stream, err);

    if (!quicly_recvstate_transfer_complete(&(stream->recvstate)))
        quicly_request_stop(stream, err);

    stream->callbacks = &quicly_stream_noop_callbacks;

    return;
}


void close_quic_stream_in_session(session_t *session, quicly_error_t err)
{
    quicly_stream_t *stream = session->stream;

    terminate_quic_stream(stream, err);

    session->stream_active = false;

    return;
}

void delete_session_init_from_tcp(session_t *s, int errno)
{

     assert(s != NULL);

     char str_src[128], str_dst[128];
     inet_ntop(AF_INET, &s->req.sa.sin_addr, str_src, sizeof(str_src));
     inet_ntop(AF_INET, &s->req.da.sin_addr, str_dst, sizeof(str_dst));

     log_debug("closing session handling tcp %d, [%s:%d <-> %s:%d] with errno %d, \"%s\"\n.",
                   s->fd, str_src, ntohs(s->req.sa.sin_port), str_dst, ntohs(s->req.da.sin_port),
                   errno, strerror(errno));

     close_tcp_conn(s);

     close_quic_stream_in_session(s, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));

     delete_session_from_t2q(&ht_tcp_to_quic, s);
     delete_session_from_q2t(&ht_quic_to_flow, s);

     s->stream = NULL;
     free(s);

     return;


}

void delete_session_init_from_quic(session_t *s, quicly_error_t err)
{
     extern session_t *ht_tcp_to_quic, *ht_quic_to_flow;
     assert(s != NULL);

     char str_src[128], str_dst[128];
     inet_ntop(AF_INET, &s->req.sa.sin_addr, str_src, sizeof(str_src));
     inet_ntop(AF_INET, &s->req.da.sin_addr, str_dst, sizeof(str_dst));

     log_debug("closing session handling stream  %ld, [%s:%d <-> %s:%d] with quicly errno %ld.\n",
                   s->stream_id, str_src, ntohs(s->req.sa.sin_port), str_dst, ntohs(s->req.da.sin_port),
                   err);

     close_quic_stream_in_session(s, err);
     close_tcp_conn(s);

     delete_session_from_t2q(&ht_tcp_to_quic, s);
     delete_session_from_q2t(&ht_quic_to_flow, s);
     s->stream = NULL;
     free(s);
}


void clean_udp_session(session_t *s, quicly_error_t err)
{
     close_quic_stream_in_session(s,  err);
     delete_session_q2f(&ht_quic_to_flow, s);
     delete_session_u2q(&ht_udp_to_quic, s);
     s->stream = NULL;
     return;
}

void client_remove_inactive_udp_sessions(void)
{
     struct timeval now;
     session_t *s, *temp;

     HASH_ITER(hh_u2q, ht_udp_to_quic, s, temp) {
         if (s->stream_active == false) {
             log_info("udp session [stream: %ld] marked inactive . \n", s->stream_id);
             delete_session_q2f(&ht_quic_to_flow, s);
             delete_session_u2q(&ht_udp_to_quic, s);
             free(s);
         }
     }
}

void remove_inactive_udp_sessions(void)
{
     struct timeval now;
     gettimeofday(&now, NULL);

     session_t *s, *temp;
     HASH_ITER(hh_u2q, ht_udp_to_quic, s, temp) {
         long int elapsed_sec = now.tv_sec - s->active_tm.tv_sec;
         if (elapsed_sec > udp_inactive_thresh_secs) {
             print_session_event(s, "dropped_pkts: %ld, dropped_bytes: %ld, state: terminating, reason: inactive.\n",
                                     s->stats.dropped_udp_pkts, s->stats.dropped_udp_bytes);
             clean_udp_session(s,  QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
             free(s);
         }
     }
}

void print_session_event(session_t *s, const char *fmt, ...)
{
    char buf[1024];
    va_list args;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    struct timeval *tv = malloc(sizeof(struct timeval));
    struct timeval *diff = malloc(sizeof(struct timeval));
    gettimeofday(tv, NULL);

    char str_sa[128];
    char str_da[128];

    snprintf(str_sa, sizeof(str_sa), "%s:%d", inet_ntoa(s->req.sa.sin_addr), ntohs(s->req.sa.sin_port));
    snprintf(str_da, sizeof(str_da), "%s:%d", inet_ntoa(s->req.da.sin_addr), ntohs(s->req.da.sin_port));
    timeval_subtract(diff, tv, &s->start_tm);

    int num_streams = 0;
    if (s && s->conn)
        num_streams = quicly_num_streams(s->conn);

    struct tm *tm_info;
    char time_string[128];
    tm_info = localtime(&tv->tv_sec);
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(stdout, "Time: %s, conn: %s -> %s, proto: %d, start_tm: %ld, elapsed_tm: %ld.%06lu, fd: %d, stream: %ld, %s",
              time_string, \
              str_sa, str_da, s->req.protocol, \
              s->start_tm.tv_sec, \
              diff->tv_sec, diff->tv_usec,   \
              s->fd, s->stream_id, buf);
    fflush(stdout);
    free(tv);
    free(diff);

    return;
}

