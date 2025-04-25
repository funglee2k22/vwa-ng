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
#include <picotls/../../t/util.h> 

static quicly_context_t client_ctx;
static quicly_cid_plaintext_t next_cid;
static ptls_iovec_t resumption_token; 

static quicly_error_t client_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
static quicly_stream_open_t stream_open = {client_on_stream_open};

conn_stream_pair_node_t mmap_head; 


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
    int tcp_fd = find_tcp_conn(mmap_head.next, stream);

    if (tcp_fd < 0) { 
        log_debug("stream: %ld, could not find tcp_sk peer to write.\n", stream->stream_id);
        return;
    }

    size_t bytes_sent = send(tcp_fd, buff, len, 0);    
    if (bytes_sent == -1) { 
        log_debug("[stream: %ld -> tcp: %d], tcp send() failed\n", stream->stream_id, tcp_fd);
        return;
    }

    log_debug("[stream: %ld -> tcp: %d], bytes: %ld sent\n", stream->stream_id, tcp_fd, bytes_sent);

    /* initiate connection close after receiving all data */
    if (quicly_recvstate_transfer_complete(&stream->recvstate))
        quicly_close(stream->conn, 0, "");

    return;
}

static void client_on_stop_sending(quicly_stream_t *stream, quicly_error_t err)
{
    log_debug("received STOP_SENDING: %lu \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    log_debug("stream: %ld received STOP_SENDING, and called quicly_close()\n", stream->stream_id);
}

static void client_on_receive_reset(quicly_stream_t *stream, quicly_error_t err)
{
    log_debug("received RESET_STREAM: %lu \n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
    log_debug("stream: %ld received reset_stream, and called quicly_close()\n", stream->stream_id);
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
        fprintf(stderr, "func: %s, line: %d, gethostbyname failed\n", __func__, __LINE__);
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr, hp->h_addr, hp->h_length);
   
    if (quicly_connect(conn, &client_ctx, srv, (struct sockaddr *)&sa, NULL, &next_cid, resumption_token, NULL, NULL, NULL) != 0) {
        log_debug("quicly_connect() failed to connect with %s:%d\n", 
            inet_ntoa(((struct sockaddr_in *)&sa)->sin_addr),  ntohs(((struct sockaddr_in *)&sa)->sin_port));
        return -1;
    }

    log_debug("quicly_connect() connected with %s:%d successful\n", 
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
           log_debug("quicly_receive returned %i\n", ret);
           return;
        } 
       
    }

    return ; 
}

int quicly_write_msg_to_buff(quicly_stream_t *stream, void *buf, size_t len)
{ 
    if (stream == NULL || !quicly_sendstate_is_open(&stream->sendstate)) {
        log_debug("stream is null or sendstate is not open. \n"); 
        return -1;
    }	
    
    quicly_streambuf_egress_write(stream, buf, len);

    return 0;
}

int write_quic_to_udp(int fd, quicly_stream_t *quic_stream) 
{ 
    quicly_address_t dest, src;
    struct iovec dgrams[10];
    uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * client_ctx.transport_params.max_udp_payload_size];
    size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);
  
    if (quic_stream == NULL || !quicly_sendstate_is_open(&quic_stream->sendstate)) {
        log_debug("stream: %ld, sendstate_is_open: 0 \n", quic_stream->stream_id);
        return -1;
    }

    if (quic_stream != NULL && quic_stream->conn == NULL) {
        log_debug("stream: %ld, conn is NULL \n", quic_stream->stream_id);
        return -1;
    }

    int ret = quicly_send(quic_stream->conn, &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));
    
    if (ret == 0 && num_dgrams > 0) { 
        size_t j;
        for (j = 0; j != num_dgrams; ++j) {
            struct msghdr mess = {.msg_name = &dest.sa, .msg_namelen = quicly_get_socklen(&dest.sa), 
                                      .msg_iov = &dgrams[j], .msg_iovlen = 1};
            sendmsg(fd, &mess, MSG_DONTWAIT);
        }
        log_debug("[stream: %ld] sent %zu dgrams to UDP sockets: %d\n", quic_stream->stream_id, num_dgrams, fd);
    } else if(ret == 0 && num_dgrams == 0) { 
        log_debug("[stream: %ld] quicly_send() nothing to send.\n", quic_stream->stream_id);
    } else if (ret == QUICLY_ERROR_FREE_CONNECTION) { 
        log_debug("[stream: %ld] connection closed (ret=%d).\n", quic_stream->stream_id, ret);
    } else { 
        log_debug("[stream: %ld] quicly_send returns with error (ret=%d).\n", quic_stream->stream_id, ret);
    } 

    return ret;
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

int send_egress_udp_packets(int fd, quicly_conn_t *conn) 
{ 
    quicly_address_t dest, src;
    struct iovec dgrams[10];
    uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * client_ctx.transport_params.max_udp_payload_size];
    size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);

    log_debug("entering...\n");

    int ret = quicly_send(conn, &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));

    log_debug("quicly_send returns %d\n", ret);
    
    if (ret == 0 && num_dgrams > 0) {
        //someting to send;
        size_t j;
        for (j = 0; j != num_dgrams; ++j) {
            struct msghdr mess = {.msg_name = &dest.sa, .msg_namelen = quicly_get_socklen(&dest.sa), 
                                    .msg_iov = &dgrams[j], .msg_iovlen = 1};
            sendmsg(fd, &mess, MSG_DONTWAIT);
            log_debug("sent %ld bytes message to remote.\n", dgrams[j].iov_len);
        }
    } else if (ret == QUICLY_ERROR_FREE_CONNECTION) { 
        log_debug("ret: %d, connection closed (by remote peer ?).\n", ret);
    } else if (ret == 0 && num_dgrams == 0) {
        log_debug("ret: %d, nums_dgrams: %ld, nothing to send.\n", ret, num_dgrams);
    } else { 
        log_debug("ret: %d, quicly_send() failed.\n", ret);
    }
    return ret;
}

void *tcp_socket_handler(void *data)
{ 
    worker_data_t *worker = (worker_data_t *)data;
    int fd = worker->tcp_fd;
    quicly_stream_t *stream = worker->stream; 

    log_debug("starting TCP socket handler...\n"); 

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
                log_debug("TCP sk [%d] read error.\n", fd);
                break;
            }

	    if (bytes_received == 0)  
		continue;

	    log_debug("tcp: %d -> stream: %ld, read %d bytes, content:  \n%.*s\n", 
			    fd, stream->stream_id, bytes_received, bytes_received, buff);

            if (quicly_write_msg_to_buff(stream, buff, bytes_received) != 0) { 
                log_debug("quicly_write_msg_to_buff() failed.\n");
                break;
            }

            log_debug("[tcp: %d -> stream: %ld]  write %d bytes from tcp to quic stream egress buf.\n", fd, stream->stream_id, bytes_received);
        }
    }

    log_debug("TCP socket handler exiting...\n");
    close(fd);
    return NULL;
} 

void *udp_socket_handler(void *data) 
{  
    worker_data_t *worker = (worker_data_t *)data;
    int quic_fd = worker->quic_fd;
    quicly_conn_t *conn = worker->conn; 

    log_debug("starting UDP socket handler...\n"); 
    
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
                log_debug("quicly_write_msg_to_buff() failed.\n");
                break;
            }
	    //TODO  always to have something to send, 
            //log_debug("write keep-alive msg successfully.\n");
#endif
	}

        //if anything needs to be sent
        quicly_address_t dest, src;
        struct iovec dgrams[10];
        uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * client_ctx.transport_params.max_udp_payload_size];
        size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);

        int ret = quicly_send(conn, &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));

        if (ret == 0 && num_dgrams > 0) {
            //someting to send;
            size_t j;
            for (j = 0; j != num_dgrams; ++j) {
                struct msghdr mess = {.msg_name = &dest.sa, .msg_namelen = quicly_get_socklen(&dest.sa),
                                          .msg_iov = &dgrams[j], .msg_iovlen = 1};
                sendmsg(quic_fd, &mess, MSG_DONTWAIT);
                log_debug("sent %ld bytes message to quic server.\n", dgrams[j].iov_len);
            }
        } else if (ret == QUICLY_ERROR_FREE_CONNECTION) {
            log_debug("ret: %d, connection closed.\n", ret);
        } else if (ret == 0 && num_dgrams == 0) {
            //log_debug("ret: %d, nums_dgrams: %ld, nothing to send.\n", ret, num_dgrams);
        }	
    }
    log_debug("UDP socket handler exiting...\n");
    close(quic_fd);
    return NULL;
}


void get_tcp_orig_dst(int fd, struct sockaddr_in *dst)
{
    socklen_t len = sizeof(*dst); 

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

#ifdef SO_ORIGINAL_DST       	
    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, dst, &len) != 0) {
        log_debug("getsockopt() error:  \n");
        return;
    }
#endif
    log_debug("TCP connection original destination addr.: %s:%d\n", 
                inet_ntoa(((struct sockaddr_in *)dst)->sin_addr), 
                ntohs(((struct sockaddr_in *)dst)->sin_port));
    return;
}


int main(int argc, char **argv)
{ 
    char *srv = "192.168.30.1"; 
    short srv_port = 4433, tcp_lstn_port = 8443; 
    int tcp_fd;   
    
    setup_client_ctx(); 
    
    int quic_fd = create_udp_client_socket(srv, srv_port);
    if (quic_fd < 0) {
        log_debug("failed to create QUIC/udp client socket to connect host %s:%d\n", srv, srv_port);
        return -1;
    }

    quicly_conn_t *conn = NULL; 
    int ret = create_quic_conn(srv, srv_port, &conn); 
    if (ret < 0) {
        log_debug("failed to create quic connection to host %s:%d\n", srv, srv_port);
        return -1;
    }

    quicly_stream_t *ctrl_stream = NULL; 
    if ((ret = quicly_open_stream(conn, &ctrl_stream, 0)) != 0) { 
        log_debug("quic conn failed to open quicly_open_stream() failed: (ret: %d)\n", ret);
        return -1;
    } 
    
    quicly_write_msg_to_buff(ctrl_stream, "hello world!\n", strlen("hello world!"));

    worker_data_t *data = (worker_data_t *)malloc(sizeof(worker_data_t));
    data->quic_fd = quic_fd;
    data->conn = conn;

    pthread_t worker_thread;
    pthread_create(&worker_thread, NULL, udp_socket_handler, (void *)data);
    
    pthread_detach(worker_thread);
    log_debug("UDP socket handler thread created.\n");

    tcp_fd = create_tcp_listener(tcp_lstn_port);
    if (tcp_fd < 0) {
        log_debug("failed to create tcp listener on port %d\n", tcp_lstn_port);
        return -1;
    }

    struct sockaddr_in tcp_remote_addr;
    socklen_t tcp_addr_len = sizeof(tcp_remote_addr); 

    while (1) {

	int client_fd = accept(tcp_fd, (struct sockaddr *)&tcp_remote_addr, &tcp_addr_len);
        if (client_fd < 0) {
            log_debug("tcp_sk: %d accept() failed.\n", tcp_fd);
            close(tcp_fd);
            break;
        }


        log_debug("accepted a new TCP connection from %s:%d\n", 
            inet_ntoa(tcp_remote_addr.sin_addr), ntohs(tcp_remote_addr.sin_port));

	struct sockaddr_in tcp_orig_addr;
        get_tcp_orig_dst(client_fd, &tcp_orig_addr);

        log_debug("original dst to %s:%d\n", 
            inet_ntoa(tcp_orig_addr.sin_addr), ntohs(tcp_orig_addr.sin_port));
        
        quicly_stream_t *nstream = NULL; 
        if ((ret = quicly_open_stream(conn, &nstream, 0)) != 0) { 
            log_debug("quic conn failed to open quicly_open_stream() failed: (ret: %d)\n", ret);
            close(client_fd);
            continue;
        }

        if (quicly_write_msg_to_buff(nstream, (void *)&tcp_orig_addr, tcp_addr_len) != 0) { 
            log_debug("sending original connection header failed.\n");
            close(client_fd);
            continue;
        }

        conn_stream_pair_node_t  *node = (conn_stream_pair_node_t *)malloc(sizeof(conn_stream_pair_node_t));
        node->fd = client_fd;
        node->stream = nstream;
        node->next = mmap_head.next;
        mmap_head.next = node;
        log_debug("added new tcp_sk: %d, quic stream: %ld to mmap list.\n", client_fd, nstream->stream_id);
        
        worker_data_t *data = (worker_data_t *)malloc(sizeof(worker_data_t));
        data->tcp_fd = client_fd;
        data->conn = conn;
        data->stream = nstream;
        pthread_t tcp_worker_thread;

        pthread_create(&tcp_worker_thread, NULL, tcp_socket_handler, (void *)data);
        pthread_detach(tcp_worker_thread);
        log_debug("TCP socket handler thread %ld created for [tcp: %d <-> stream: %ld].\n", 
            tcp_worker_thread, tcp_fd, nstream->stream_id);
      }
       
}



