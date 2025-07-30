#include "common.h"

#include <arpa/inet.h>
#include <ev.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <math.h>
#include <memory.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <quicly.h>
#include <quicly/defaults.h>
#include <quicly/streambuf.h>
#include <picotls/../../t/util.h>
#include <picotls/openssl.h>


ssize_t  streambuf_high_watermarker = STREAMBUF_HIGH_WARTER_MARKER;


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

void print_stream_event(quicly_stream_t *s, const char *fmt, ...)
{
    char buf[1024];
    va_list args;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    struct timeval tv;
    gettimeofday(&tv, NULL);

    fprintf(stdout, "Time: %ld.%06lu, stream: %ld, %s", tv.tv_sec, tv.tv_usec, s->stream_id, buf);

    fflush(stdout);

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
    struct tm *tm_info;
    struct timeval tv;
    char time_string[128];

    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);

    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(stdout, "%s.%06ld, func: %s, line: %d, %s", time_string, tv.tv_usec, function, line, buf);
    fflush(stdout);
#endif

    return;
}

int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

void print_req_info(struct sockaddr_in *src, struct sockaddr_in *dst, ssize_t len)
{

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src->sin_addr.s_addr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst->sin_addr.s_addr, dst_ip, sizeof(dst_ip));

    log_info("received UDP packet from %s:%u to %s:%u, udp_len: %ld \n",
                src_ip, ntohs(src->sin_port), dst_ip, ntohs(dst->sin_port), len);
    return;
}

int open_tun_dev(const char *devname)
{
    struct ifreq ifr;
    int fd, err;
    if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
        perror("open /dev/net/tun");
        exit(1);
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, devname, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) == -1) {
        perror("ioctl TUNSETIFF");
        close(fd);
        exit(1);
    }

    return fd;
}


int create_udp_raw_socket(int tun_fd)
{
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (raw_sock < 0) {
        perror("socket(AF_INET, SOCK_RAW)");
        close(tun_fd);
        exit(1);
    }

    int on = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(tun_fd);
        close(raw_sock);
        exit(1);
    }

    return raw_sock;
}


ssize_t get_quicly_stream_egress_qlen(quicly_stream_t *stream)
{
    quicly_streambuf_t *sbuf = (quicly_streambuf_t *)stream->data;
    quicly_sendbuf_t *sb = (quicly_sendbuf_t *) & sbuf->egress;
    long int stream_id = stream->stream_id;

    ssize_t i, total = 0;
    for (i = 0; i != sb->vecs.size; ++i) {
        quicly_sendbuf_vec_t *vec = sb->vecs.entries + i;
        total += vec->len;
    }
    total = total - sb->off_in_first_vec;
    //printf("stream %ld, total: %ld, size: %ld,  off_in_first_vec: %ld\n", stream_id, total, sb->vecs.size, sb->off_in_first_vec);
    return total;
}


ssize_t estimate_quicly_stream_egress_qlen(quicly_stream_t *stream)
{
    quicly_streambuf_t *sbuf = (quicly_streambuf_t *)stream->data;
    quicly_sendbuf_t *sb = (quicly_sendbuf_t *) & sbuf->egress;
    long int stream_id = stream->stream_id;

    if (sb->vecs.size == 0)
        return 0;

    ssize_t mid = (sb->vecs.size / 2);

    quicly_sendbuf_vec_t *vec = sb->vecs.entries + mid;

    ssize_t total = sb->vecs.size * (vec->len);

    log_debug("stream %ld, estimate total: %ld, vecs.size: %ld, mid_len: %ld, bytes_written: %ld.\n",
               stream_id, total, sb->vecs.size, vec->len, sb->bytes_written);

    return total;
}





