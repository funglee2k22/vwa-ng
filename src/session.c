#include "session.h"
#include "uthash.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>

extern session_t *ht_tcp_to_quic, *ht_quic_to_flow;

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

     HASH_FIND(hh_q2f, *hh, &stream, sizeof(stream), t);
     if (t == NULL) {
        HASH_ADD(hh_q2f, *hh, stream, sizeof(stream), s);
     } else {
        HASH_REPLACE(hh_q2f, *hh, stream, sizeof(stream), s, t);
     }
     return;
}

session_t *find_session_q2f(session_t **hh, quicly_stream_t *stream)
{
    session_t *r = NULL;

    HASH_FIND(hh_q2f, *hh, &stream, sizeof(stream), r);

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

    request_t key;
    memcpy(&key, &(s->req), sizeof(request_t));
    r = NULL;

    HASH_FIND(hh_u2q, *hh, &key, sizeof(request_t), r);
    if (!r) {
        log_error("here.\n");
    }
    printf("adding key -> session\n");
    dump_request(&key);

    r = find_session_u2q(hh, &key);

    if (!r) {
        log_error("here.\n");
    }

    return;
}

session_t *find_session_u2q(session_t **hh, request_t *k)
{
    session_t *r = NULL;

    dump_request(k);

    HASH_FIND(hh_u2q, *hh, k, sizeof(request_t), r);

    if (!r) {
       log_error("could not find the session\n");
    }

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



