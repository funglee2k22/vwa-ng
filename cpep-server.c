#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <pthread.h>
#include <openssl/pem.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <ev.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "common.h"
#include <picotls/../../t/util.h>

static quicly_context_t server_ctx;
static quicly_cid_plaintext_t next_cid;
quicly_conn_t *conns[256] = {NULL};

//tcp_to_stream_map_node_t *tcp_to_stream_map = NULL;  //used to lookup
stream_to_tcp_map_node_t *stream_to_tcp_map = NULL;  //used to lookup tcp fd by stream id
//quicly_conn_map_node_t *conns = NULL;  //used to lookup quic connection by src addr

static quicly_error_t server_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
static void server_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn,
                                    quicly_error_t err, uint64_t frame_type, const char *reason, size_t reason_len);
static quicly_stream_open_t on_stream_open = {server_on_stream_open};
static quicly_closed_by_remote_t closed_by_remote = {server_on_conn_close};

static void server_on_stop_sending(quicly_stream_t *stream, quicly_error_t err)
{
    log_error("stream: %ld received STOP_SENDING: %lu \n", stream->stream_id, QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void ctrl_stream_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    log_debug("stream: %ld received control message.\n", stream->stream_id);

    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0) {
        fprintf(stderr, "no data in control stream receive buffer.\n");
        return;
    }

    log_debug("QUIC stream [%ld], bytes_received: %zu\n", stream->stream_id, input.len);
    log_debug("msg:\"%.*s\"\n", (int)input.len, (char *)input.base);
    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);

    return;
}

int cpep_srv_read_tcp_to_stream(int fd, quicly_stream_t *stream)
{
    char buf[4096];
    ssize_t bytes_received; 
   
    if (fd < 0 || stream == NULL) { 
        log_error("invalid fd %d or stream %p.\n", fd, stream);
        return -1;
    }

    while(bytes_received = recv(fd, buf, sizeof(buf), 0) > 0) {
        if (stream && !quicly_sendstate_is_open(&stream->sendstate)) 
            quicly_get_or_open_stream(stream->conn, stream->stream_id, &stream);
        
        if (quicly_streambuf_egress_write(stream, buf, bytes_received) != 0) {
            log_error("stream: %ld write to stream buffer failed.\n", stream->stream_id);
            return -1;
        }

    }

    if (bytes_received == 0) { 
        log_error("tcp connection %d closed receiving EOF.\n", fd);
        close(fd);
        return 0;   
    }

    return 0;
}

void *handle_isp_server(void *data)
{
    quicly_conn_t *quic_conn = ((worker_data_t *) data)->conn;
    quicly_stream_t *quic_stream = ((worker_data_t *) data)->stream; 
    long stream_id = quic_stream -> stream_id;
    int tcp_fd = ((worker_data_t *) data)->tcp_fd;

    //log_debug("worker: %ld handles tcp: %d -> stream: %ld\n", pthread_self(), tcp_fd, quic_stream->stream_id);

    while (1) {
        fd_set readfds;
        struct timeval tv = {.tv_sec = 0, .tv_usec = 10000};
        do {
            FD_ZERO(&readfds);
            FD_SET(tcp_fd, &readfds);
        } while (select(tcp_fd + 1, &readfds, NULL, NULL, &tv) == -1);

        if (FD_ISSET(tcp_fd, &readfds)) {
            if( cpep_srv_read_tcp_to_stream(tcp_fd, quic_stream) != 0) {
                //log_error("worker: %ld, failed to read from tcp fd %d.\n", pthread_self(), tcp_fd);
                break;
            }
        }
    }

error:

    remove_stream_ht(quic_stream->stream_id);
    close(tcp_fd);
    //quicly_streambuf_egress_shutdown(quic_stream);
    return NULL;
}

static void server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{

    log_debug("stream: %ld receive buffer.\n", stream->stream_id);

    if (stream->stream_id == 0) {
        ctrl_stream_on_receive(stream, off, src, len);
        return;
    }

    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    if (input.len == 0) {
        log_warn("stream: %ld no data in receive buffer.\n", stream->stream_id);
        return;
    }

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);

    void *buff_base = input.base;
    int  buff_len = input.len;

    log_debug("QUIC stream [%ld], %ld bytes received,\n", stream->stream_id, input.len);

    int tcp_fd = find_tcp_by_stream_id(stream->stream_id);

    struct sockaddr_in orig_dst;
    size_t addr_len = sizeof(orig_dst);

    if (tcp_fd < 0) {
        memcpy(&orig_dst, input.base, sizeof(orig_dst));
        buff_len -= addr_len;
        buff_base += addr_len;

        tcp_fd = create_tcp_connection((struct sockaddr *)&orig_dst);

        if (tcp_fd < 0) {
            log_error("failed to create TCP conn. to dest %s:%d.\n",
                    inet_ntoa(((struct sockaddr_in *)&orig_dst)->sin_addr),
                    ntohs(((struct sockaddr_in *)&orig_dst)->sin_port));
            return;
        }

        log_debug("created TCP conn. %d to dest %s:%d.\n", tcp_fd,
                    inet_ntoa(((struct sockaddr_in *)&orig_dst)->sin_addr),
                    ntohs(((struct sockaddr_in *)&orig_dst)->sin_port));

        add_stream_tcp_peer(stream->stream_id, tcp_fd);

        worker_data_t *data = (worker_data_t *)malloc(sizeof(worker_data_t));
        data->tcp_fd = tcp_fd;
        data->conn = stream->conn;
        data->stream = stream;

        pthread_t worker_thread;
        pthread_create(&worker_thread, NULL, handle_isp_server, (void *)data);
        log_info("worker: %ld, handle [quic: %ld <- tcp: %d] to %s:%d\n",
                        worker_thread, stream->stream_id, tcp_fd,
                        inet_ntoa(((struct sockaddr_in *)&orig_dst)->sin_addr),
                        ntohs(((struct sockaddr_in *)&orig_dst)->sin_port));

        pthread_detach(worker_thread);
    }

    if (tcp_fd <= 0) {
        log_error("stream: %ld failed to create TCP peer to dest %s:%d.\n",
                stream->stream_id,
                inet_ntoa(((struct sockaddr_in *)&orig_dst)->sin_addr),
                ntohs(((struct sockaddr_in *)&orig_dst)->sin_port));
        return;
    }

    ssize_t bytes_sent; 
    while (bytes_sent = send(tcp_fd, buff_base, buff_len, 0) == -1)
        ;;
    
    if (bytes_sent == -1) {
        log_error("stream: %ld, tcp fd: %d send() failed\n", stream->stream_id, tcp_fd);
        return;
    }

    log_debug("stream: %ld, tcp: %d, bytes: %ld sent\n", stream->stream_id, tcp_fd, bytes_sent);      
    
    return;
}

static void server_on_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    log_info("stream: %ld received RESET_STREAM: %lu \n", stream->stream_id, QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void server_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn, quicly_error_t err,
    uint64_t frame_type, const char *reason, size_t reason_len)
{
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        log_warn("transport close:code=0x%lu ;frame=%lu ;reason=%.*s\n",
                QUICLY_ERROR_GET_ERROR_CODE(err), frame_type, (int)reason_len, reason);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        log_warn("application close:code=0x%lu ;reason=%.*s\n",
                QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len, reason);
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        log_warn("stateless reset\n");
    } else
        log_warn("unexpected close:code=%ld\n", err);

    quicly_free(conn);
    return;
}

static quicly_error_t server_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy,
        quicly_streambuf_egress_shift,
        quicly_streambuf_egress_emit,
        server_on_stop_sending,
        server_on_receive,
        server_on_receive_reset
    };
    int ret;
    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
        return ret;

    stream->callbacks = &stream_callbacks;

    log_debug("stream: %ld is openned.\n", stream->stream_id);

    return ret;
}

static inline quicly_conn_t *find_conn(struct sockaddr_storage *sa, socklen_t salen, quicly_decoded_packet_t *packet)
{
    return NULL;
}

static void inline cpep_srv_handle_packet(quicly_decoded_packet_t *packet, struct sockaddr_in *sa, socklen_t salen)
{
    int ret, i;
    
    for(i = 0; conns[i] != NULL; ++i) {
        if(quicly_is_destination(conns[i], NULL, (struct sockaddr *) sa, packet)) {
            break;
        }
    }

    if (conns[i] == NULL) { 
        ret = quicly_accept(conns + i, &server_ctx, 0, (struct sockaddr *) sa, packet, NULL, &next_cid, NULL, NULL);
        if (ret != 0) {
            log_error("failed to accept quic connection with error %d.\n", ret);
            return;
        }
        log_info("find a new connection from: %s:%d.\n", inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));
        ++next_cid.master_id;
    } else { 
        ret = quicly_receive(conns[i], NULL, (struct sockaddr *) sa, packet);
        if (ret != 0 && ret != QUICLY_ERROR_PACKET_IGNORED) {
            log_error("failed to receive quic packet with error %d.\n", ret);
            return;
        }
    }
    return;
}


int cpep_srv_read_udp(int quic_fd)
{ 
    char buf[4096];
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
    struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1}; 
    quicly_decoded_packet_t packet;
    ssize_t bytes_received;

    while ((bytes_received = recvmsg(quic_fd, &msg, 0) != -1)) {
        for (size_t offset = 0; offset < bytes_received; ) { 
            size_t packet_len = quicly_decode_packet(&server_ctx, &packet, msg.msg_iov[0].iov_base, bytes_received, &offset);
            if (packet_len == SIZE_MAX) {
                log_error("failed to decode QUIC packet.\n");
                return;
            }
            cpep_srv_handle_packet(&packet, &sa, salen);
        }
    }

    if (errno != EWOULDBLOCK) {
        log_error("recvfrom() failed with error (%d): %s\n", errno, strerror(errno));
        return -1;
    }

    return 0;
}

void run_server_loop(int quic_srv_fd)
{
    log_info("starting server loop with UDP sk: %d...\n", quic_srv_fd);

    while (1) {
        struct timeval tv = {.tv_sec = 0, .tv_usec = 10000};
        fd_set readfds;

        do {
            FD_ZERO(&readfds);
            FD_SET(quic_srv_fd, &readfds);
        } while (select(quic_srv_fd + 1, &readfds, NULL, NULL, &tv) == -1);

        if (FD_ISSET(quic_srv_fd, &readfds)) {
            if (cpep_srv_read_udp(quic_srv_fd) != 0) {
                log_error("failed to read from UDP socket %d.\n", quic_srv_fd);
                continue;
            }            
        }

        /* send QUIC packets, if any */
        for (size_t i = 0; conns[i] != NULL; ++i) {
	        int ret = send_pending(server_ctx, quic_srv_fd, conns[i]);
            if (ret != 0) {
                log_error("sending quic dgrams failed on udp socket %d with errori ret = %d.\n", quic_srv_fd, ret);
                continue;
            }
        } 
    } /* End of While loop */

error:
    log_error("server loop exiting.\n");
    close(quic_srv_fd);
}

void  setup_quicly_ctx(const char *cert, const char *key, const char *logfile)
{
    setup_session_cache(get_tlsctx());
    quicly_amend_ptls_context(get_tlsctx());

    server_ctx = quicly_spec_context;
    server_ctx.tls = get_tlsctx();
    quicly_amend_ptls_context(server_ctx.tls);
    server_ctx.stream_open = &on_stream_open;
    server_ctx.closed_by_remote = &closed_by_remote;
    server_ctx.transport_params.max_stream_data.uni = UINT32_MAX;
    server_ctx.transport_params.max_stream_data.bidi_local = UINT32_MAX;
    server_ctx.transport_params.max_stream_data.bidi_remote = UINT32_MAX;
    server_ctx.init_cc = &quicly_cc_cubic_init;
    server_ctx.initcwnd_packets = 10;

    load_certificate_chain(server_ctx.tls, cert);
    load_private_key(server_ctx.tls, key);

    return;
}

int main(int argc, char **argv)
{
    char *host = "127.0.0.1";     //quic server address
    short udp_listen_port = 4433;   //port is quic server listening UDP port
    char *cert_path = "server.crt";
    char *key_path = "server.key";
    extern const char *__progname;
    quicly_stream_open_t stream_open = {server_on_stream_open};
    setup_quicly_ctx(cert_path, key_path, NULL);

    //setup logging
    openlog(__progname, LOG_PID, LOG_DEBUG);

    //create a UDP socket used by quicly
    int quic_srv_fd = create_udp_listener(udp_listen_port);
    if (quic_srv_fd < 0) {
        log_error("failed to create UDP listener on port %d.\n", udp_listen_port);
        return -1;
    }

    log_info("QPEP Server is running, pid: %lu, UDP listening port: %d, sk_fd: %d\n",
            (uint64_t)getpid(), udp_listen_port, quic_srv_fd);

    run_server_loop(quic_srv_fd);

    log_info("QPEP Server is exiting.\n");

cleanup:
    for (size_t i = 0; conns[i] != NULL; ++i) {
        quicly_free(conns[i]);
        conns[i] = NULL;
    }
    if (quic_srv_fd > 0)
        close(quic_srv_fd);
    closelog();
    return 0;

}
