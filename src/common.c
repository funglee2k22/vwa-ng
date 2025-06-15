#include "common.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <memory.h>
#include <picotls/openssl.h>
#include <quicly.h>
#include <quicly/streambuf.h>
#include <errno.h>

ptls_context_t *get_tlsctx()
{
    static ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
                                    .get_time = &ptls_get_time,
                                    .key_exchanges = ptls_openssl_key_exchanges,
                                    .cipher_suites = ptls_openssl_cipher_suites,
                                    .require_dhe_on_psk = 1};
    return &tlsctx;
}

struct addrinfo *get_address(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result;

    printf("resolving %s:%s\n", host, port);

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family = AF_UNSPEC; // Let getaddrinfo decide if it's a hostname.
    hints.ai_socktype = SOCK_DGRAM;                 /* Datagram socket */
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    hints.ai_protocol = IPPROTO_UDP;

    int s = getaddrinfo(host, port, &hints, &result);
    if(s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return NULL;
    } else {
        return result;
    }
}

bool send_dgrams_default(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams)
{
    static ssize_t total_quic_sent, output_thresh;
    for(size_t i = 0; i < num_dgrams; ++i) {
        struct msghdr mess = {
            .msg_name = dest,
            .msg_namelen = quicly_get_socklen(dest),
            .msg_iov = &dgrams[i], .msg_iovlen = 1
        };

        ssize_t bytes_sent;
        while ((bytes_sent = sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
            ;

        if (bytes_sent == -1) {
            perror("sendmsg failed");
            return false;
        }
        total_quic_sent += bytes_sent;
        if (total_quic_sent >= output_thresh) {
            output_thresh += 10 * 1024 * 1024;
            printf("send_dgram_default total %ld bytes sent\n", total_quic_sent);
        }
    }
    return true;
}

bool (*send_dgrams)(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams) = send_dgrams_default;

bool send_pending(quicly_context_t *ctx, int fd, quicly_conn_t *conn)
{
    #define SEND_BATCH_SIZE 16

    quicly_address_t dest, src;
    struct iovec dgrams[SEND_BATCH_SIZE];
    uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * ctx->transport_params.max_udp_payload_size];
    size_t num_dgrams = SEND_BATCH_SIZE;
    size_t send_dgrams_c = 0;

    while(true) {
        num_dgrams = PTLS_ELEMENTSOF(dgrams);
        int quicly_res = quicly_send(conn, &dest, &src, dgrams, &num_dgrams, &dgrams_buf, sizeof(dgrams_buf));

        if(quicly_res != 0) {
            if(quicly_res != QUICLY_ERROR_FREE_CONNECTION) {
                printf("quicly_send failed with code %i\n", quicly_res);
            } else {
                log_warn("connection closed (closeable) quicly_res: %d \n", quicly_res);
                print_trace();
            }
            return false;
        } else if(num_dgrams == 0) { //nothing to send
            return true;
        }

        if (!send_dgrams(fd, &dest.sa, dgrams, num_dgrams)) {
            return false;
        }
    }
    return true;
}


int set_non_blocking(int sockfd)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (fcntl(sockfd, F_SETFL, (flags < 0 ? 0 : flags) | O_NONBLOCK) == -1) {
        perror("set_non_blocking");
        return -1;
    }
    return 0;
}

void print_trace (void)
{
    void *array[10];
    char **strings;
    int size, i;

    size = backtrace (array, 10);
    strings = backtrace_symbols (array, size);
    if (strings != NULL) {
        printf ("Obtained %d stack frames.\n", size);
        for (i = 0; i < size; i++)
            printf ("%s\n", strings[i]);
    }
    free (strings);
}

void _debug_printf(int priority, const char *function, int line, const char *fmt, ...)
{
    char buf[1024];
    va_list args;

    if (priority > LOG_INFO)
	return;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
#if 0
    syslog(priority, "func: %s, line: %d, %s", function, line, buf);
#else
    time_t current_time = time(NULL);
    struct tm *time_info  = localtime(&current_time);
    char time_string[256];
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S" , time_info);
    fprintf(stdout, "%s, func: %s, line: %d, %s", time_string, function, line, buf);
    fflush(stdout);
#endif

    return;
}

void tcp_write_cb(EV_P_ ev_io *w, int revents)
{
    int fd = w->fd;
    extern session_t *ht_tcp_to_quic; 
    session_t *s = find_session_t2q(&ht_tcp_to_quic, fd);

    if (!s) {
        printf("could not find quic connection for tcp fd: %d.\n", fd);
        ev_io_stop(loop, w);
        free(w);
        close(fd);
        return;
    }

    quicly_stream_t *stream = quicly_get_stream(s->conn, s->stream_id);
    assert(stream != NULL);

    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    if (input.len == 0) {
        // nothing to be sent, and we can stop the watcher.
        ev_io_stop(loop, w);
        return;
    }
    size_t off = ((quicly_streambuf_t *) (stream->data))->ingress.off;
    size_t bytes_sent = -1;
    while ((bytes_sent = write(s->fd, input.base, input.len)) > 0) {
        input.base += bytes_sent;
        input.len -= bytes_sent;
        quicly_streambuf_ingress_safe_shift(stream, off, bytes_sent);
        if (input.len == 0)
             break;
    }

    if (bytes_sent == -1) {
       if (errno == EAGAIN || errno == EWOULDBLOCK) {
            log_info("tcp %d write is blocked with error %d, %s\n",
                                                     fd, errno, strerror(errno));
        } else {
            // if error happens other than EAGAIN. it is a failure, terminate the session.
            log_info("tcp %d write error %d, %s\n", fd, errno, strerror(errno));
            clean_up_from_tcp(&ht_tcp_to_quic, fd);
            return;
        }
    }

    return;
}
