#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/syscall.h>
#include "uthash.h"
#include "quicly.h" 
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include <picotls/../../t/util.h>


typedef struct stream_to_tcp_map_node { 
    long int stream_id;
    int fd;
    UT_hash_handle hh; // makes this structure hashable 
} stream_to_tcp_map_node_t;

typedef struct tcp_to_stream_map_node { 
    int fd; 
    quicly_stream_t *stream;
    UT_hash_handle hh; // makes this structure hashable
} tcp_to_stream_map_node_t;

typedef struct quicly_conn_map_node { 
    struct sockaddr_in addr;
    quicly_conn_t *conn;
    UT_hash_handle hh; // makes this structure hashable
} quicly_conn_map_node_t;


struct conn_stream_pair_node; 
typedef struct conn_stream_pair_node { 
    union {
        int fd;
        long int stream_id; 
    };
    quicly_stream_t *stream;
    struct conn_stream_pair_node *next; 
    UT_hash_handle hh; // makes this structure hashable
} conn_stream_pair_node_t;

typedef struct pthread_work { 
    int tcp_fd;
    int quic_fd;
    quicly_conn_t *conn; 
    quicly_stream_t *stream; 
} worker_data_t; 

typedef struct cpep_server_parameters {
    char *server_ip;
    char *server_certificate_path;
    char *server_key_path;
    short server_udp_port;
} server_parameters_t; 


void _debug_printf(int priority, const char *function, int line, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

#ifdef quicly_debug_printf
#undef quicly_debug_printf
#endif 

#define log_debug(...)  _debug_printf(LOG_DEBUG, __func__, __LINE__, __VA_ARGS__)
#define log_info(...)   _debug_printf(LOG_INFO, __func__, __LINE__, __VA_ARGS__)
#define log_warn(...)   _debug_printf(LOG_WARNING,__func__, __LINE__, __VA_ARGS__) 
#define log_error(...)  _debug_printf(LOG_ERR, __func__, __LINE__, __VA_ARGS__)

int find_tcp_conn(conn_stream_pair_node_t *head, quicly_stream_t *stream);

ptls_context_t *get_tlsctx();

int create_tcp_listener(short port);

int create_udp_client_socket(char *hostname, short port);

bool send_dgrams_default(int fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams);

int quicly_send_msg(int quic_fd, quicly_stream_t *stream, void *buf, size_t len);

int create_tcp_connection(struct sockaddr *sa);

int create_udp_listener(short port);

int get_opts_server(int argc, char *argv[], server_parameters_t *paras); 
