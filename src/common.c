#include "common.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <math.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <memory.h>
#include <picotls/openssl.h>
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


void print_session_event(session_t *s, const char *fmt, ...)
{
    char buf[1024];
    va_list args;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    struct timeval *tv = malloc(sizeof(struct timeval));
    struct timeval *diff = malloc(sizeof(struct timeval));
    gettimeofday(tv, NULL);

    char str_sa[128];
    char str_da[128];

    snprintf(str_sa, sizeof(str_sa), "%s:%d", inet_ntoa(s->sa.sin_addr), ntohs(s->sa.sin_port));
    snprintf(str_da, sizeof(str_da), "%s:%d", inet_ntoa(s->da.sin_addr), ntohs(s->da.sin_port));
    timeval_subtract(diff, tv, &s->start_tm);

    int num_streams = 0; 
    if (s && s->conn)
        num_streams = quicly_num_streams(s->conn);

    fprintf(stdout, "Time: %ld.%06lu, conn: %s -> %s, start_tm: %ld.%06lu, elapsed_tm: %ld.%06lu, fd: %d, stream: %ld, totol_stream: %d, %s",
             tv->tv_sec, tv->tv_usec, str_sa, str_da,
              s->start_tm.tv_sec, s->start_tm.tv_usec,
              diff->tv_sec, diff->tv_usec,
              s->fd, s->stream_id, num_streams, buf);
    fflush(stdout);
    free(tv);
    free(diff);

    return;
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

