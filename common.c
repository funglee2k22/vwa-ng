
#include <sys/socket.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <memory.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include "common.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"


#undef USE_SYSLOG

ptls_context_t *get_tlsctx()
{
    static ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
                                    .get_time = &ptls_get_time,
                                    .key_exchanges = ptls_openssl_key_exchanges,
                                    .cipher_suites = ptls_openssl_cipher_suites,
                                    .require_dhe_on_psk = 1};
    return &tlsctx;
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
#ifdef USE_SYSLOG
    syslog(priority, "func: %s, line: %d, %s", function, line, buf);
#else
    current_time = time(NULL);
    struct tm *time_info  = localtime(&current_time); 
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S" , time_info);
    fprintf(stdout, "%s, func: %s, line: %d, %s", time_string, function, line, buf);
#endif
    return;
}


int find_tcp_conn(conn_stream_pair_node_t *head, quicly_stream_t *stream)
{
    conn_stream_pair_node_t *p = head;
    int i = 0;
    while (p) {
        if (p->stream == stream)
            return p->fd;
    i++;
    p = p->next;
    }
    return -1;
}

int create_tcp_connection(struct sockaddr *sa)
{
    int fd;
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        log_debug("socket failed");
        return -1;
    }

    if (connect(fd, sa, sizeof(struct sockaddr)) == -1) {
        log_debug("connect with %s:%dfailed",
                inet_ntoa(((struct sockaddr_in *)sa)->sin_addr),
                ntohs(((struct sockaddr_in *)sa)->sin_port));
        close(fd);
        return -1;
    }

    log_debug("created tcp sk [%d] to connect %s:%d.\n", fd,
                inet_ntoa(((struct sockaddr_in *)sa)->sin_addr),
                ntohs(((struct sockaddr_in *)sa)->sin_port));

    return fd;
}

int create_tcp_listener(short port)
{
    int fd;
    struct sockaddr_in sa;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        log_error("socket failed");
        return -1;
    }
#if 0
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return -1;
    }
#endif

    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &(int){1}, sizeof(int)) != 0) {
        log_error("setsockopt(IP_TRANSPARENT) failed");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (void *)&sa, sizeof(sa)) != 0) {
        log_error("bind failed");
        return -1;
    }

    if (listen(fd, 128) != 0) {
        log_error("listen failed");
        return -1;
    }

    return fd;
}

int create_udp_listener(short port)
{
    int fd;
    struct sockaddr_in sa;
    int reuseaddr = 1;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        log_error("socket failed");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) != 0) {
        log_error("setsockopt(SO_REUSEADDR) failed");
        return -1;
    }

    if (bind(fd, (void *)&sa, sizeof(sa)) != 0) {
        log_error("bind failed");
        return -1;
    }

    return fd;
}

int create_udp_client_socket(char *hostname, short port)
{
    int fd;
    struct sockaddr_in sa;
    struct hostent *hp;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        log_error("socket failed");
        return -1;
    }

    if ((hp = gethostbyname(hostname)) == NULL) {
        log_error("gethostbyname failed");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr, hp->h_addr, hp->h_length);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        log_error("connect failed");
        return -1;
    }

    return fd;
}

int get_original_dest_addr(int fd, struct sockaddr_storage *sa)
{
    socklen_t salen = sizeof(*sa);

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, sa, &salen) != 0) {
        log_error("getsockopt(SO_ORIGINAL_DST) failed");
        return -1;
    }

    return 0;
}

bool send_dgrams_default(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams)
{
    for(size_t i = 0; i < num_dgrams; ++i) {
        struct msghdr mess = {
            .msg_name = dest,
            .msg_namelen = quicly_get_socklen(dest),
            .msg_iov = &dgrams[i], .msg_iovlen = 1
        };

        ssize_t bytes_sent;
        while ((bytes_sent = sendmsg(fd, &mess, 0)) == -1 && errno == EINTR);
        if (bytes_sent == -1) {
            log_error("sendmsg failed");
            return false;
        }
    }

    return true;
}

bool send_dgrams(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams)
{
    for(size_t i = 0; i < num_dgrams; ++i) {
        struct msghdr mess = {
            .msg_name = dest,
            .msg_namelen = quicly_get_socklen(dest),
            .msg_iov = &dgrams[i], .msg_iovlen = 1
        };

        ssize_t bytes_sent;
        while ((bytes_sent = sendmsg(fd, &mess, 0)) == -1)
                ;

        if (bytes_sent == -1) {
            log_error("sendmsg failed");
            return false;
        }

    }

    return true;
}

void remove_tcp_ht(tcp_to_stream_map_node_t *tcp_to_quic_ht, stream_to_tcp_map_node_t *quic_to_tcp_ht, int fd)
{
    tcp_to_stream_map_node_t *s;
    HASH_FIND_INT(ht, &fd, s);

    if (s) {
       quicly_stream_t *stream = s->stream;
       HASH_DEL(tcp_to_quic_ht, s);
       remove_stream_ht(quic_to_tcp_ht, stream);
    }

    return;
}

void remove_stream_ht(stream_to_tcp_map_node_t *quic_to_tcp_ht, tcp_to_stream_map_node_t *tcp_to_quic_ht, quicly_stream_t *stream)
{
    stream_to_tcp_map_node_t *s;
    HASH_FIND_INT(quic_to_tcp_ht, &(stream -> stream_id), s);

    if (s) {
        int fd = s->fd;
        HASH_DEL(ht, s);
        remove_tcp_ht(tcp_to_quic_ht, fd);
    }

    return;
}

void update_stream_tcp_conn_maps(stream_to_tcp_map_node_t *stream_to_tcp_map,
                                 tcp_to_stream_map_node_t *tcp_to_stream_map,
                                 int fd, quicly_stream_t *stream)
{
    stream_to_tcp_map_node_t *s;
    tcp_to_stream_map_node_t *t;

    HASH_FIND_INT(stream_to_tcp_map, &stream->stream_id, s);
    if (s == NULL) {
        s = (stream_to_tcp_map_node_t *)malloc(sizeof(stream_to_tcp_map_node_t));
        s->stream_id = stream->stream_id;
        s->fd = fd;
        HASH_ADD_INT(stream_to_tcp_map, stream_id, s);
    } else {
        s->fd = fd;
        log_warn("stream_to_tcp_map updated <stream: %ld -> TCP: %d >.\n", stream->stream_id, fd);
    }

    HASH_FIND_INT(tcp_to_stream_map, &fd, t);
    if (t == NULL) {
        t = (tcp_to_stream_map_node_t *)malloc(sizeof(tcp_to_stream_map_node_t));
        t->fd = fd;
        t->stream = stream;
        HASH_ADD_INT(tcp_to_stream_map, fd, t);
    } else {
        t->stream = stream;
        log_warn("tcp_to_stream_map updated <TCP: %d -> stream: %ld >.\n", fd, stream->stream_id);
    }

    return;
}

int find_tcp_conn_ht(stream_to_tcp_map_node_t *ht, int stream_id)
{
    stream_to_tcp_map_node_t *s;

    HASH_FIND_INT(ht, &stream_id, s);
    if (s == NULL) {
        log_WARN("No TCP conn peer found for QUIC stream [%d].\n", stream_id);
        return -1;
    }
    return s->fd;
}

