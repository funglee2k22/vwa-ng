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


void delete_session_from_hh(session_t **t2q, session_t **q2t, session_t *s)
{
    if (!s)
        return;

    if (t2q)
        HASH_DELETE(hh_t2q, *t2q, s);

    if (q2t)
        HASH_DELETE(hh_q2t, *q2t, s);

    return;
}

void detach_stream(quicly_stream_t *stream)
{
    log_debug("entering detach_stream\n");
    if (stream->callbacks)
        stream->callbacks = &quicly_stream_noop_callbacks;
    if (stream->data)
        stream->data = NULL;
    //stream = NULL;

}


void close_stream(quicly_stream_t *stream, quicly_error_t err)
{
    if (!quicly_sendstate_transfer_complete(&(stream->sendstate)))
        quicly_reset_stream(stream, err);

    if (!quicly_recvstate_transfer_complete(&(stream->recvstate)))
        quicly_request_stop(stream, err);
    //session free session
}

static inline void release_resources(session_t *s)
{
    if (!s)
        return;

    if (s->tcp_read_watcher) {
        ev_io_stop(loop, s->tcp_read_watcher);
        free(s->tcp_read_watcher);
    }

    if (s->tcp_write_watcher) {
        ev_io_stop(loop, s->tcp_write_watcher);
        free(s->tcp_write_watcher);
    }

    if (s->t2q_buf)
        free(s->t2q_buf);

    return;
}

static void close_session(session_t *session)
{
    extern session_t *ht_tcp_to_quic, *ht_quic_to_tcp;

    assert(session != NULL);

    //remove session from hash_table
    delete_session_from_hh(&ht_tcp_to_quic, &ht_quic_to_tcp, session);

    release_resources(session);

    //closing quic stream
    quicly_stream_t *stream = quicly_get_stream(session->conn, session->stream_id);

    if (stream && stream->stream_id != 0) {
        close_stream(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0));
        //detach_stream(stream);
    }

    //close tcp fd
    close(session->fd);

    free(session);

    return;
}

void clean_up_from_tcp(session_t **hh, int fd)
{
    session_t *session = find_session_t2q(hh, fd);

    if (!session) {
        log_warn("could not find session infomation for tcp fd %d. \n", fd);
        return;
    }

    //log_info("closing session for  tcp fd %d <-> quic stream %ld. \n", fd, session->stream->stream_id);
    if (!(session->stream))
        log_debug("closing session for  tcp fd %d <-> quic stream %ld stream has been closed. \n",
                            fd, session->stream_id);

    close_session(session);

    return;
}

void clean_up_from_stream(session_t **hh, quicly_stream_t *stream, quicly_error_t err)
{
    assert(stream != NULL);
    session_t *session = find_session_q2t(hh, stream->stream_id);

    if (!session) {
        log_warn("could not find session infomation quic stream  %ld. \n", stream->stream_id);
        close_stream(stream, err);
        detach_stream(stream);
        return;
    }

    log_debug("closing session for tcp fd %d <-> quic stream %ld with quicly error code (%ld). \n",
                                   session->fd, session->stream->stream_id, err);

    //note: we override the quicly error code for stream close.
    if (err != QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0)) {
        log_error("quicly stream %ld, closed w/ error %ld.\n", stream->stream_id, err);
    }

    close_session(session);

    return;
}



