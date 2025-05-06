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
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "pthread.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "common.h"
#include "uthash.h"
#include <picotls/../../t/util.h>

static quicly_context_t client_ctx;
static quicly_cid_plaintext_t next_cid;
static ptls_iovec_t resumption_token;

static quicly_error_t client_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
static quicly_stream_open_t stream_open = {client_on_stream_open};

stream_to_tcp_map_node_t *stream_to_tcp_map = NULL;  //used to lookup tcp fd by stream id

static void client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{

    log_debug("stream: %ld on_receive cb is called\n", stream->stream_id);

    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    log_debug("stream: %ld received %zu bytes\n", stream->stream_id, input.len);

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);

    char buff[4096];
    memcpy(buff, input.base, len);
    int tcp_fd = find_tcp_by_stream_id(stream_to_tcp_map, stream->stream_id);

    if (tcp_fd < 0) {
        log_error("stream: %ld, could not find tcp_sk peer to write.\n", stream->stream_id);
        return;
    }

    size_t bytes_sent = send(tcp_fd, buff, len, 0);
    if (bytes_sent == -1) {
        log_error("[stream: %ld -> tcp: %d], tcp send() failed\n", stream->stream_id, tcp_fd);
        return;
    }

    log_debug("[stream: %ld -> tcp: %d], bytes: %ld sent\n", stream->stream_id, tcp_fd, bytes_sent);

    /* initiate connection close after receiving all data */
    if (quicly_recvstate_transfer_complete(&stream->recvstate)) { 
        log_info("stream: %ld received all data, and calling quicly_close()\n", stream->stream_id);
        quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    }

    return;
}

static void client_on_stop_sending(quicly_stream_t *stream, quicly_error_t err)
{
    log_info("received STOP_SENDING: %lu \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    log_info("stream: %ld received STOP_SENDING, and called quicly_close()\n", stream->stream_id);
}

static void client_on_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    log_info("received RESET_STREAM: %lu \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    log_info("stream: %ld received reset_stream, and called quicly_close()\n", stream->stream_id);
}

static quicly_error_t client_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy,
        quicly_streambuf_egress_shift,
        quicly_streambuf_egress_emit,
        client_on_stop_sending,
        client_on_receive,
        client_on_receive_reset
    };
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
        return ret;
    stream->callbacks = &stream_callbacks;

    log_debug("stream: %ld opened.\n", stream->stream_id);
    return 0;
}

void setup_client_ctx()
{
    setup_session_cache(get_tlsctx());
    quicly_amend_ptls_context(get_tlsctx());

    client_ctx = quicly_spec_context;
    client_ctx.tls = get_tlsctx();
    client_ctx.stream_open = &stream_open;
    client_ctx.transport_params.max_stream_data.uni = UINT32_MAX;
    client_ctx.transport_params.max_stream_data.bidi_local = UINT32_MAX;
    client_ctx.transport_params.max_stream_data.bidi_remote = UINT32_MAX;
    //client_ctx.init_cc = &quicly_cc_cubic_init;

    return;
}

int create_quic_conn(char *srv, short port, quicly_conn_t **conn)
{
    struct sockaddr_in sa;
    struct hostent *hp;

    if ((hp = gethostbyname(srv)) == NULL) {
        log_error("gethostbyname failed\n");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr, hp->h_addr_list[0], hp->h_length);

    if (quicly_connect(conn, &client_ctx, srv, (struct sockaddr *)&sa, NULL, &next_cid, resumption_token, NULL, NULL, NULL) != 0) {
        log_error("quicly_connect() failed to connect with %s:%d\n",
            inet_ntoa(((struct sockaddr_in *)&sa)->sin_addr),  ntohs(((struct sockaddr_in *)&sa)->sin_port));
        return -1;
    }

    log_info("quicly_connect() connected with %s:%d successful\n",
        inet_ntoa(((struct sockaddr_in *)&sa)->sin_addr),  ntohs(((struct sockaddr_in *)&sa)->sin_port));

    return 0;
}

void process_quicly_msg(int quic_fd, quicly_conn_t *conn, struct msghdr *msg, ssize_t dgram_len)
{
    size_t off = 0;
    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        size_t packet_len = quicly_decode_packet(&client_ctx, &decoded, msg->msg_iov[0].iov_base, dgram_len, &off);
        if (packet_len == SIZE_MAX)
            break;

        int ret = quicly_receive(conn, NULL, msg->msg_name, &decoded);
        if (ret != 0 && ret != QUICLY_ERROR_PACKET_IGNORED) {
           log_error("quicly_receive returned %i\n", ret);
           return;
        }
    }
    return ;
}

int quicly_write_msg_to_buff(quicly_stream_t *stream, void *buf, size_t len)
{
    if (stream == NULL || !quicly_sendstate_is_open(&stream->sendstate)) {
        log_error("stream is null or sendstate is not open. \n");
        return -1;
    }

    quicly_streambuf_egress_write(stream, buf, len);
    
    return 0;
}


int read_ingress_udp_message(int fd, quicly_conn_t *conn)
{
    uint8_t buf[4096];
    struct sockaddr_storage sa;
    struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
    struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};

    ssize_t rret;
    while ((rret = recvmsg(fd, &msg, 0)) == -1 && errno == EINTR)
        ;

    log_debug("read %ld bytes data from UDP sockets [%d]\n", rret, fd);

    if (rret > 0)
        process_quicly_msg(fd, conn, &msg, rret);

    return 0;
}

void *tcp_socket_handler(void *data)
{
    worker_data_t *worker = (worker_data_t *)data;
    int fd = worker->tcp_fd;
    quicly_stream_t *stream = worker->stream;

    log_info("starting TCP socket handler thread %ld [tcp: %d <-> stream: %ld].\n", 
                    pthread_self(), fd, stream->stream_id);
    
    while (1) {
        fd_set readfds;
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};

        do {
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
        } while (select(fd + 1, &readfds, NULL, NULL, &tv) == -1);

        if (FD_ISSET(fd, &readfds)) {
            char buff[4096];
            int bytes_received = read(fd, buff, sizeof(buff));
            if (bytes_received < 0) {
                log_error("TCP sk [%d] read error.\n", fd);
                break;
            }

            if (bytes_received == 0)
                continue;

            log_debug("tcp: %d -> stream: %ld, read %d bytes, content:  \n%.*s\n",
                        fd, stream->stream_id, bytes_received, bytes_received, buff);

            if (quicly_write_msg_to_buff(stream, buff, bytes_received) != 0) {
                log_error("quicly_write_msg_to_buff() failed.\n");
                break;
            }

            log_debug("[tcp: %d -> stream: %ld]  write %d bytes from tcp to quic stream egress buf.\n", fd, stream->stream_id, bytes_received);
        }
    }
cleanup:
    log_info("closing [tcp: %d <-> stream: %ld...\n", fd, stream->stream_id);
    remove_stream_ht(stream_to_tcp_map, stream->stream_id);
    //free(stream);
    close(fd);
    return NULL;
}

void *udp_socket_handler(void *data)
{
    worker_data_t *worker = (worker_data_t *)data;
    int quic_fd = worker->quic_fd;
    quicly_conn_t *conn = worker->conn;

    log_info("starting UDP socket handler %ld for quic_fd: %d...\n", pthread_self(), quic_fd);

    while (1) {
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        fd_set readfds;

        do {
            FD_ZERO(&readfds);
            FD_SET(quic_fd, &readfds);
        } while (select(quic_fd + 1, &readfds, NULL, NULL, &tv) == -1);

        if (FD_ISSET(quic_fd, &readfds)) {
            read_ingress_udp_message(quic_fd, conn);
        } else {

#if 0
            quicly_stream_t *ctrl_stream = quicly_get_stream(conn, 0);
            if (quicly_write_msg_to_buff(ctrl_stream, "client is still alive!", strlen("client is still alive!")) != 0) {
                log_error("quicly_write_msg_to_buff() failed.\n");
                break;
            }
#endif
        }
    
        int ret = send_quic_dgrams(client_ctx, quic_fd, conn);
        if (ret != 0)
            log_error("sending quic dgrams failed with error %d", ret);

    }
cleanup:
    log_debug("UDP socket handler %ld handling UDP fd %d exiting, closing...\n", pthread_self(), quic_fd);
    close(quic_fd);
    return NULL;
}



int main(int argc, char **argv)
{
    char *srv = "192.168.30.1";
    short srv_port = 4433, tcp_lstn_port = 8443;
    int tcp_fd;

    setup_client_ctx();

    int quic_fd = create_udp_client_socket(srv, srv_port);
    if (quic_fd < 0) {
        log_error("failed to create QUIC/udp client socket to connect host %s:%d\n", srv, srv_port);
        return -1;
    }

    quicly_conn_t *conn = NULL;
    int ret = create_quic_conn(srv, srv_port, &conn);
    if (ret < 0) {
        log_error("failed to create quic connection to host %s:%d\n", srv, srv_port);
        return -1;
    }

    quicly_stream_t *ctrl_stream = NULL;
    if ((ret = quicly_open_stream(conn, &ctrl_stream, 0)) != 0) {
        log_error("quic conn failed to open quicly_open_stream() failed: (ret: %d)\n", ret);
        return -1;
    }
    
    char *hello_msg = "quic client connected!\n";
    quicly_write_msg_to_buff(ctrl_stream, hello_msg, strlen(hello_msg));

    worker_data_t *data = (worker_data_t *)malloc(sizeof(worker_data_t));
    data->quic_fd = quic_fd;
    data->conn = conn;

    pthread_t worker_thread;
    pthread_create(&worker_thread, NULL, udp_socket_handler, (void *)data);
    pthread_detach(worker_thread);

    tcp_fd = create_tcp_listener(tcp_lstn_port);
    if (tcp_fd < 0) {
        log_error("failed to create tcp listener on port %d\n", tcp_lstn_port);
        return -1;
    }

    struct sockaddr_in tcp_remote_addr;
    socklen_t tcp_addr_len = sizeof(tcp_remote_addr);

    while (1) {

    int client_fd = accept(tcp_fd, (struct sockaddr *)&tcp_remote_addr, &tcp_addr_len);
        if (client_fd < 0) {
            log_error("tcp_sk: %d accept() failed.\n", tcp_fd);
            goto cleanup;
        }

        struct sockaddr_in tcp_orig_addr;
        get_orignal_dest_addr(client_fd, &tcp_orig_addr);

        log_info("accepted a new TCP [%d] connection [%s:%d --> %s:%d\n", client_fd,
            inet_ntoa(tcp_remote_addr.sin_addr), ntohs(tcp_remote_addr.sin_port),
            inet_ntoa(tcp_orig_addr.sin_addr), ntohs(tcp_orig_addr.sin_port));

        quicly_stream_t *nstream = NULL;
        if ((ret = quicly_open_stream(conn, &nstream, 0)) != 0) {
            log_error("quic conn failed to open quicly_open_stream() for tcp %d with (ret: %d)\n", client_fd, ret);
            close(client_fd);
            continue;
        }
        
        if (quicly_write_msg_to_buff(nstream, (void *)&tcp_orig_addr, tcp_addr_len) != 0) {
            log_error("sending original connection header failed.\n");
            close(client_fd);
            continue;
        }

        add_stream_tcp_peer(nstream->stream_id, client_fd);

        worker_data_t *data = (worker_data_t *)malloc(sizeof(worker_data_t));
        data->tcp_fd = client_fd;
        data->conn = conn;
        data->stream = nstream;
        pthread_t tcp_worker_thread;

        pthread_create(&tcp_worker_thread, NULL, tcp_socket_handler, (void *)data);
        pthread_detach(tcp_worker_thread);
    }

cleanup:
    close(quic_fd);
    close(tcp_fd);
    return 0;
}



