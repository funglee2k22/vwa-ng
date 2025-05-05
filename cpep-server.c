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

tcp_to_stream_map_node_t *tcp_to_stream_map = NULL;  //used to lookup
stream_to_tcp_map_node_t *stream_to_tcp_map = NULL;  //used to lookup tcp fd by stream id
//quicly_conn_map_node_t *conns = NULL;  //used to lookup quic connection by src addr

static quicly_error_t server_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
static void server_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn,
                                    quicly_error_t err, uint64_t frame_type, const char *reason, size_t reason_len);
static quicly_stream_open_t on_stream_open = {server_on_stream_open};
static quicly_closed_by_remote_t closed_by_remote = {server_on_conn_close};

static void server_on_stop_sending(quicly_stream_t *stream, quicly_error_t err)
{
    log_info("stream: %ld received STOP_SENDING: %lu \n", stream->stream_id, QUICLY_ERROR_GET_ERROR_CODE(err));
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

void *handle_isp_server(void *data)
{
    quicly_conn_t *quic_conn = ((worker_data_t *) data)->conn;
    quicly_stream_t *quic_stream = ((worker_data_t *) data)->stream;
    int tcp_fd = ((worker_data_t *) data)->tcp_fd;

    log_debug("worker: %ld handles tcp: %d -> stream: %ld\n", pthread_self(), tcp_fd, quic_stream->stream_id);

    while (1) {
        fd_set readfds;
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        do {
            FD_ZERO(&readfds);
            FD_SET(tcp_fd, &readfds);
        } while (select(tcp_fd + 1, &readfds, NULL, NULL, &tv) == -1);

        if (FD_ISSET(tcp_fd, &readfds)) {
            char buff[4096];
            int bytes_received = read(tcp_fd, buff, sizeof(buff));

            if (bytes_received < 0) {
                log_debug("[tcp: %d -> stream: %ld] tcp side read error.\n", tcp_fd, quic_stream->stream_id);
                goto error;
            }

            log_debug("[tcp: %d -> stream: %ld], received \n %.*s \n", tcp_fd, quic_stream->stream_id, bytes_received,  buff);

            if (!quicly_sendstate_is_open(&quic_stream->sendstate) && (bytes_received > 0))
                quicly_get_or_open_stream(quic_stream->conn, quic_stream->stream_id, &quic_stream);

            if (quic_stream && quicly_sendstate_is_open(&quic_stream->sendstate) && (bytes_received > 0)) {
                quicly_streambuf_egress_write(quic_stream, buff, bytes_received);

                /* shutdown the stream after sending all data */
                if (quicly_recvstate_transfer_complete(&quic_stream->recvstate))
                     quicly_streambuf_egress_shutdown(quic_stream);

                log_debug("[tcp: %d -> stream: %ld] write %d bytes to quic stream: %ld.\n",
                        tcp_fd, quic_stream->stream_id, bytes_received, quic_stream->stream_id);
            } else {
                log_debug("[tcp: %d -> stream: %ld] quic stream is closed or no data to write.\n",
                        tcp_fd, quic_stream->stream_id);
                break;
            }
        }
    }

error:
    remove_tcp_ht(tcp_to_stream_map, stream_to_tcp_map, tcp_fd);
    close(tcp_fd);
    //TODO close QUIC stream also
    free(data);
    free(quic_stream);
    return NULL;
}

static void server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{

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
    int tcp_fd = find_tcp_conn_ht(stream_to_tcp_map, stream->stream_id);

    if (tcp_fd < 0) {
        struct sockaddr_in orig_dst;

        memcpy(&orig_dst, input.base, sizeof(orig_dst));
        buff_len -= len;
        buff_base += len;

        tcp_fd = create_tcp_connection((struct sockaddr *)&orig_dst);

        if (tcp_fd < 0) {
            log_debug("failed to create TCP conn. to dest %s:%d.\n",
                    inet_ntoa(((struct sockaddr_in *)&orig_dst)->sin_addr),
                    ntohs(((struct sockaddr_in *)&orig_dst)->sin_port));
            return;
        }

        log_debug("created TCP conn. %d to dest %s:%d.\n", tcp_fd,
                    inet_ntoa(((struct sockaddr_in *)&orig_dst)->sin_addr),
                    ntohs(((struct sockaddr_in *)&orig_dst)->sin_port));
 
        register_stream_tcp_pair(tcp_fd, stream);
        
        worker_data_t *data = (worker_data_t *)malloc(sizeof(worker_data_t));
        data->tcp_fd = tcp_fd;
        data->conn = stream->conn;
        data->stream = stream;

        pthread_t worker_thread;
        pthread_create(&worker_thread, NULL, handle_isp_server, (void *)data);
        log_debug("worker: %ld, handle [quic: %ld <- tcp: %d]\n", worker_thread, stream->stream_id, tcp_fd);
    }

    if (tcp_fd > 0 && buff_len > 0) {
        ssize_t bytes_sent = send(tcp_fd, buff_base, buff_len, 0);
        if (bytes_sent == -1) {
            log_debug("[stream: %ld -> tcp: %d], tcp send() failed\n", stream->stream_id, tcp_fd);
            close(tcp_fd);
            return;
        }
        log_debug("[stream: %ld -> tcp: %d], bytes: %zu sent\n", stream->stream_id, tcp_fd, bytes_sent);
        log_debug("[stream: %ld -> tcp: %d], msg: %.*s sent\n", stream->stream_id, tcp_fd, (int) bytes_sent, (char *) buff_base);
    }

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

    log_info("stream: %ld is openned.\n", stream->stream_id);

    return ret;
}


static void process_quicly_msg(int quic_fd, quicly_conn_t **conns, struct msghdr *msg, size_t dgram_len)
{
    size_t off = 0, i;

    /* split UDP datagram into multiple QUIC packets */
    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&server_ctx, &decoded, msg->msg_iov[0].iov_base, dgram_len, &off) == SIZE_MAX) {
            return;
        }

        for (i = 0; conns[i] != NULL; ++i)
            if (quicly_is_destination(conns[i], NULL, msg->msg_name, &decoded))
                break;

        if (conns[i] != NULL) {
            /* let the current connection handle ingress packets */
            log_debug("reuse the current connection.\n");
            quicly_receive(conns[i], NULL, msg->msg_name, &decoded);
        } else {
            /* assume that the packet is a new connection */
            quicly_accept(conns + i, &server_ctx, NULL, msg->msg_name, &decoded, NULL, &next_cid, NULL, NULL);
            log_info("find a new connection.\n");
        }
    }

    return;
}

void run_server_loop(int quic_srv_fd)
{
    log_info("starting server loop with UDP sk: %d...\n", quic_srv_fd);

    while (1) {
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        fd_set readfds;

        do {
            FD_ZERO(&readfds);
            FD_SET(quic_srv_fd, &readfds);
        } while (select(quic_srv_fd + 1, &readfds, NULL, NULL, &tv) == -1);

        if (FD_ISSET(quic_srv_fd, &readfds)) {
            //TODO this could be a function
            uint8_t buf[4096];
            struct sockaddr_storage sa;
            struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
            struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
            ssize_t rret;
            while ((rret = recvmsg(quic_srv_fd, &msg, 0)) == -1 && errno == EINTR)
                ;
            log_debug("read %ld bytes data from UDP sockets [%d]\n", rret, quic_srv_fd);
            if (rret > 0)
                process_quicly_msg(quic_srv_fd, conns, &msg, rret);
        } else {
            log_debug("no data from UDP socket, idling\n");
        }

        /* send QUIC packets, if any */
        for (size_t i = 0; conns[i] != NULL; ++i) {
            quicly_address_t dest, src;
            struct iovec dgrams[10];
            uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * server_ctx.transport_params.max_udp_payload_size];
            size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);
            int ret = quicly_send(conns[i], &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));

            switch (ret) {
            case 0: {
                size_t j;
                for (j = 0; j != num_dgrams; ++j) {
                    struct msghdr mess = {.msg_name = &dest.sa, .msg_namelen = quicly_get_socklen(&dest.sa),
                                          .msg_iov = &dgrams[j], .msg_iovlen = 1};
                    sendmsg(quic_srv_fd, &mess, MSG_DONTWAIT);
                }
                break;
            }
            case QUICLY_ERROR_FREE_CONNECTION:
                log_debug("free connection\n");
                quicly_free(conns[i]);
                conns[i] = NULL;
                break;
            default:
                log_debug("quicly_send returned with error %d\n", ret);
                goto error;
            }
        } /* End of for (size_t i = 0; conns[i] != NULL; ++i) */

    } /* End of While loop */

error:

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
