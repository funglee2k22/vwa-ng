#include "session.h"
#include "uthash.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>


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

void add_to_hash_q2t(session_t **hh, session_t *s)
{
     session_t *t = NULL;
     long int stream_id = s->stream_id;

     HASH_FIND(hh_q2t, *hh, &stream_id, sizeof(stream_id), t);
     if (t == NULL) {
        HASH_ADD(hh_q2t, *hh, stream_id, sizeof(stream_id), s);
     } else {
        HASH_REPLACE(hh_q2t, *hh, stream_id, sizeof(stream_id), s, t);
     }
     return;
}

session_t *find_session_q2t(session_t **hh, long int stream_id)
{
    session_t *r = NULL;

    HASH_FIND(hh_q2t, *hh, &stream_id, sizeof(stream_id), r);

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

    HASH_DELETE(hh_q2t, *q2t, s);

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
     extern session_t *ht_tcp_to_quic, *ht_quic_to_tcp;
     assert(s != NULL);

     char str_src[128], str_dst[128];
     inet_ntop(AF_INET, &s->sa.sin_addr, str_src, sizeof(str_src));
     inet_ntop(AF_INET, &s->da.sin_addr, str_dst, sizeof(str_dst));

     log_debug("closing session handling tcp %d, [%s:%d <-> %s:%d] with errno %d, \"%s\"\n.",
                   s->fd, str_src, ntohs(s->sa.sin_port), str_dst, ntohs(s->da.sin_port),
                   errno, strerror(errno));

     close_tcp_conn(s);

     close_quic_stream_in_session(s, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));

     delete_session_from_t2q(&ht_tcp_to_quic, s);
     delete_session_from_q2t(&ht_quic_to_tcp, s);

     s->stream = NULL;
     free(s);

     return;


}

void delete_session_init_from_quic(session_t *s, quicly_error_t err)
{
     extern session_t *ht_tcp_to_quic, *ht_quic_to_tcp;
     assert(s != NULL);

     char str_src[128], str_dst[128];
     inet_ntop(AF_INET, &s->sa.sin_addr, str_src, sizeof(str_src));
     inet_ntop(AF_INET, &s->da.sin_addr, str_dst, sizeof(str_dst));

     log_debug("closing session handling stream  %ld, [%s:%d <-> %s:%d] with quicly errno %ld.\n",
                   s->stream_id, str_src, ntohs(s->sa.sin_port), str_dst, ntohs(s->da.sin_port),
                   err);

     close_quic_stream_in_session(s, err);

     close_tcp_conn(s);

     delete_session_from_t2q(&ht_tcp_to_quic, s);
     delete_session_from_q2t(&ht_quic_to_tcp, s);
     s->stream = NULL;
     free(s);
}



