#include "server_stream.h"
#include "common.h" 
#include "uthash.h"

#include <ev.h>
#include <errno.h>
#include <stdbool.h>
#include <quicly/streambuf.h>

extern struct ev_loop *loop;

extern session_t *hh_tcp_to_quic; 
extern session_t *hh_quic_to_tcp;

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
} server_stream;

static int report_counter = 0;

void server_cleanup(int fd)
{ 
    session_t *s = NULL;

    HASH_FIND_INT(hh_tcp_to_quic, &fd, s);

    long int stream_id = (s) ? s->stream_id : -1; 
    
    if (s)  
	HASH_DEL(hh_tcp_to_quic, s);
    
    HASH_FIND_INT(hh_quic_to_tcp, &stream_id, s); 
    if (s) 
	HASH_DEL(hh_quic_to_tcp, s);
    
    //TODO quic stream close

    close(fd);

    return;
}


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
    server_stream *s = (server_stream*)stream->data;
    print_report(s);
    printf("connection %i total packets sent: %"PRIu64" total packets lost: %"PRIu64"\n", s->report_id, s->total_num_packets_sent, s->total_num_packets_lost);
    ev_timer_stop(EV_DEFAULT, &s->report_timer);
    free(s);
}

static void server_stream_send_shift(quicly_stream_t *stream, size_t delta)
{
    server_stream *s = stream->data;
    s->acked_offset += delta;
}

static void server_stream_send_emit(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all)
{
    server_stream *s = stream->data;
    uint64_t data_off = s->acked_offset + off;

    if(data_off + *len < s->target_offset) {
        *wrote_all = 0;
    } else {
        printf("done sending\n");
        *wrote_all = 1;
        *len = s->target_offset - data_off;
        assert(data_off + *len == s->target_offset);
    }

    memset(dst, 0x58, *len);
}

static void server_stream_send_stop(quicly_stream_t *stream, quicly_error_t err)
{
    printf("server_stream_send_stop stream-id=%li\n", stream->stream_id);
    fprintf(stderr, "received STOP_SENDING: %li\n", err);
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
} 


static void server_stream_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    printf("server stream %ld receive %ld bytes.\n", stream->stream_id, len);
    if (len == 0) 
	return; 

    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    
    quicly_stream_sync_recvbuf(stream, len);

    session_t *s = NULL; 
    long int stream_id = stream->stream_id;

    HASH_FIND_INT(hh_quic_to_tcp, &stream_id, s); 
    if (!s) { 
        fprintf(stderr, "could not find related session for stream %ld.\n", stream_id);
	return;
    }

    int fd = s->fd; 
    ssize_t send_bytes = send(fd, input.base, input.len, 0);
    if (send_bytes == -1) {
	perror("send (2) failed.");
        fprintf(stderr, "relay msg from quic to tcp failed with %d, %s.\n", errno, strerror(errno)); 
	return;
    }
    
    return; 

#if 0
    if(quicly_recvstate_transfer_complete(&stream->recvstate)) {
        printf("request received, sending data\n");
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

static void add_session(int fd, long int stream_id, struct sockaddr_in *sa, struct sockaddr_in *da) 
{ 
    session_t *ns = (session_t *)malloc(sizeof(session_t)); 
    ns->fd = fd; 
    ns->stream_id = stream_id; 
    memcpy(&(ns->sa), sa, sizeof(*sa)); 
    memcpy(&(ns->da), da, sizeof(*da));
    
    session_t *s = NULL; 
    HASH_FIND_INT(hh_tcp_to_quic, &fd, s);
    if (s) 
        HASH_DEL(hh_tcp_to_quic, s); 
    HASH_ADD_INT(hh_tcp_to_quic, fd, ns);

    HASH_FIND_INT(hh_quic_to_tcp, &stream_id, s);
    if (s) 
	HASH_DEL(hh_quic_to_tcp, s);
    HASH_ADD_INT(hh_quic_to_tcp, stream_id, ns); 

    return;
}

int srv_tcp_to_quic(int fd, char *buf, int len)
{ 
    session_t *s = NULL;
    
    HASH_FIND_INT(hh_tcp_to_quic, &fd, s);
    if (!s) {
	printf("could not find quic stream peer for tcp %d.\n", fd);	
        return -1;
    } 

    quicly_stream_t *stream = NULL; 
    long int stream_id = s->stream_id; 
    quicly_conn_t *conn = s->conn; 
    int ret = quicly_get_or_open_stream(conn, stream_id, &stream); 
    if (ret != 0) { 
        printf("failed to open stream %ld for tcp %d.\n", stream_id, fd);
        return -1;
    }
    quicly_streambuf_egress_write(stream, buf, len);
    //quicly_streambuf_egress_shutdown(stream);

    return 0;
} 


void server_tcp_read_cb(EV_P_ ev_io *w, int revents)
{ 
    char buf[4096];
    int fd = w->fd;
    ssize_t read_bytes = 0;

    while((read_bytes = read(fd, buf, sizeof(buf)) > 0)) {
        int ret = srv_tcp_to_quic(fd, buf, read_bytes);
        if (ret != 0) {
            printf("fd: %d failed to write into quic stream.\n", fd);
	    return;
        }
    }

    if (read_bytes == 0) {
         // tcp connection has been closed.
	 printf("fd: %d remote peer closed.\n", fd);
	 ev_io_stop(loop, w);
         server_cleanup(fd);
	 free(w);
    } else if (read_bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    //Nothing to read.
	    //printf("fd: %d noththing to read.\n");
	} else {
	    printf("fd: %d, read() failed with %d, \"%s\".\n", fd, errno, strerror(errno));
	    ev_io_stop(loop, w);
	    server_cleanup(fd);
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
 
    frame_t ctrl_frame;  
    memcpy((void *)&ctrl_frame, input.base, input.len); 
    
    if (ctrl_frame.type != 1) {
	printf("ctrl stream %ld, recv: %.*s\n", stream->stream_id, (int) input.len, (char *) input.base);
	return; 
    }
    
    session_t *p = (session_t *) &(ctrl_frame.s);
    struct sockaddr_in *da = (struct sockaddr_in *) &(p->da); 
    struct sockaddr_in *sa = (struct sockaddr_in *) &(p->sa); 
    p->conn = stream->conn; 

    int fd = create_tcp_connection((struct sockaddr *) da);
    assert(fd > 0); 
    add_session(fd, stream->stream_id, sa, da);

    printf("session quic: %ld <-> tcp: %d created.\n", stream->stream_id, fd); 

    //add socket read watcher 
    ev_io *socket_watcher = calloc(1, sizeof(ev_io)); 
    
    ev_io_init(socket_watcher, server_tcp_read_cb, fd, EV_READ);
    ev_io_start(loop, socket_watcher); 
    //TODO adding the socket watcher to session_t ?     
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
