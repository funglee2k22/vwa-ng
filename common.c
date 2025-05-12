
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
    time_t current_time = time(NULL);
    struct tm *time_info  = localtime(&current_time);
    char time_string[256];
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S" , time_info);
    fprintf(stdout, "%s, func: %s, line: %d, %s", time_string, function, line, buf);
    fflush(stdout);
#endif
    return;
}

int create_tcp_connection(struct sockaddr *sa)
{
    int fd;
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        log_error("socket failed %d, %s", errno, strerror(errno));
        return -1;
    }

    if (connect(fd, sa, sizeof(struct sockaddr)) == -1) {
        log_error("connect with %s:%d failed, %d, %s\n",
                inet_ntoa(((struct sockaddr_in *)sa)->sin_addr),
                ntohs(((struct sockaddr_in *)sa)->sin_port),
                errno, strerror(errno));
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
        log_error("socket failed with %d, %s", errno, strerror(errno));
        return -1;
    }
#if 0
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) != 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return -1;
    }
#endif

    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &(int){1}, sizeof(int)) != 0) {
        log_error("setsockopt(IP_TRANSPARENT) failed with %d, %s", errno, strerror(errno));
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (void *)&sa, sizeof(sa)) != 0) {
        log_error("bind socket %d failed with %d, %s", fd, errno, strerror(errno));
        return -1;
    }

    if (listen(fd, 128) != 0) {
        log_error("set socket %d listen failed with %d, %s", fd, errno, strerror(errno));
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
        log_error("udp socket create failed with %d, %s", errno, strerror(errno));
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

#if 0
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) != 0) {
        log_error("udp socket %d setsockopt(SO_REUSEADDR) failed with %d, %s", fd, errno, strerror(errno));
        close(fd);
        return -1;
    }
#endif

    if (bind(fd, (void *)&sa, sizeof(sa)) != 0) {
        log_error("udp socket %d bind failed with %d, %s", fd, errno, strerror(errno));
        close(fd);
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
        log_error("create udp socket failed with %d, %s", errno, strerror(errno));
        return -1;
    }

    if ((hp = gethostbyname(hostname)) == NULL) {
        log_error("gethostbyname (%s) failed with %d, %s", hostname, errno, strerror(errno));
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr, hp->h_addr, hp->h_length);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        log_error("udp socket %d connect failed with %d, %s", fd, errno, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}


int get_original_dest_addr(int fd, struct sockaddr_in *sa)
{
    socklen_t salen = sizeof(*sa);

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, sa, &salen) != 0) {
        log_error("getsockopt(SO_ORIGINAL_DST) on socket %d failed with %d, %s", fd, errno, strerror(errno));
        return -1;
    }

    return 0;
} 


int send_pending(quicly_context_t ctx, int fd, quicly_conn_t *conn)
{
    quicly_address_t dest, src;
    struct iovec dgrams[16];
    uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * ctx.transport_params.max_udp_payload_size];
    size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);

    int ret = quicly_send(conn, &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));

    if (ret == 0 && num_dgrams > 0) {
        //someting to send;
        if (!send_dgrams_default(fd, &dest.sa, dgrams, num_dgrams)) {
            log_error("send_dgrams failed\n");
            return -1;
        }
    } else if (ret == QUICLY_ERROR_FREE_CONNECTION) {
        log_error("ret: %d, connection closed.\n", ret);
    } else if (ret == 0 && num_dgrams == 0) {
        log_debug("ret: %d, nums_dgrams: %ld, nothing to send.\n", ret, num_dgrams);
    } else {
        log_error("ret: %d, udp socket %d called quicly_send() with error.\n", ret, fd);
    }
    return ret;
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

/* 
 * Hash table streamid : tcp fd related. 
 * Note: all ht related funtions are using extern variable stream_to_tcp_map
 */

void remove_stream_ht(long int stream_id)
{
    stream_to_tcp_map_node_t *s;
    extern stream_to_tcp_map_node_t *stream_to_tcp_map;

    HASH_FIND_INT(stream_to_tcp_map, &stream_id, s);

    if (s) {
        HASH_DEL(stream_to_tcp_map, s);
    }

    return;
}

void add_stream_tcp_peer(long int stream_id, int fd)
{
    stream_to_tcp_map_node_t  *s;
    extern stream_to_tcp_map_node_t *stream_to_tcp_map;

    HASH_FIND_INT(stream_to_tcp_map, &stream_id, s);
    if (s == NULL) {
        s = (stream_to_tcp_map_node_t *)malloc(sizeof *s);
        s->stream_id = stream_id; /* stream_id is the key */
        HASH_ADD_INT(stream_to_tcp_map, stream_id, s);  
    }
    s->fd = fd;
    return;
}

int find_tcp_by_stream_id(long int stream_id)
{
    stream_to_tcp_map_node_t *s = NULL;
    int key = (int) stream_id; 
    extern stream_to_tcp_map_node_t *stream_to_tcp_map; 

    HASH_FIND_INT(stream_to_tcp_map, &key, s);
    
    if (s == NULL) {
        log_debug("No TCP conn peer found for QUIC stream [%ld].\n", stream_id);
        return -1;
    }

    return s->fd;
} 



