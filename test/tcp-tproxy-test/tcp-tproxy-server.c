#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <ev.h>

#define PORT_NO 8443
#define BUFFER_SIZE 1024

int total_clients = 0;  // Total number of connected clients

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

int main()
{
   struct ev_loop *loop = ev_default_loop(0);
   int sd;
   struct sockaddr_in addr;
   struct ev_io w_accept;

   // Create server socket
   if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
       perror("socket error");
       return -1;
   }

   bzero(&addr, sizeof(addr));
   addr.sin_family = AF_INET;
   addr.sin_port = htons(PORT_NO);
   addr.sin_addr.s_addr = INADDR_ANY;

   // Bind socket to address
   if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
       perror("bind error");
   }

   int enable = 1;
   if (setsockopt(sd, SOL_IP, IP_TRANSPARENT, &enable, sizeof(int)) != 0) {
       perror("setsockopt(IP_TRANSPARENT) failed.");
       return -1;
   }

   // Start listing on the socket
   if (listen(sd, 128) < 0) {
       perror("listen error");
       return -1;
   }

   printf("starting listening on port %d.\n", PORT_NO);

   // Initialize and start a watcher to accepts client requests
   ev_io_init(&w_accept, accept_cb, sd, EV_READ);
   ev_io_start(loop, &w_accept);

   // Start infinite loop
   while (1) {
       ev_loop(loop, 0);
   }
   return 0;
}

/* Accept client requests */
void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_sd;
    struct ev_io *w_client = malloc (sizeof(struct ev_io));

    if (EV_ERROR & revents) {
        perror("got invalid event");
        return;
    }

    // Accept client request
    client_sd = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);

    if (client_sd < 0) {
        perror("accept error");
        return;
    }

    printf("tcp from %s: %d -> ",  inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    struct sockaddr_in server_addr;
    socklen_t sa_len = sizeof(server_addr);
    if (getsockopt(client_sd, SOL_IP, SO_ORIGINAL_DST, &server_addr, &sa_len) != 0) {
        perror("getsockopt(SO_ORIGINAL_DST) failed");
        exit(-1);
    }
    printf(" %s: %d w/ getsockopt(SO_ORIGINAL_DST) \n",  inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));

    bzero(&server_addr, sizeof(server_addr));
    if (getsockname(client_sd, (struct sockaddr *) &server_addr, &sa_len) != 0) {
        perror("getsockname() failed");
        exit(-1);
    }

    printf("tcp from %s: %d -> ",  inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    printf(" %s: %d w/ getsockname() \n",  inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));

    total_clients ++; // Increment total_clients count
    printf("Successfully connected with client.\n");
    printf("%d client(s) connected.\n", total_clients);

    // Initialize and start watcher to read client requests
    ev_io_init(w_client, read_cb, client_sd, EV_READ);
    ev_io_start(loop, w_client);
}

/* Read client message */
void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    char buffer[BUFFER_SIZE];
    ssize_t read;

    if (EV_ERROR & revents) {
        perror("got invalid event");
        return;
    }

    // Receive message from client socket
    read = recv(watcher->fd, buffer, BUFFER_SIZE, 0);

    if (read < 0) {
        perror("read error");
        return;
    }

    if (read == 0) {
        // Stop and free watchet if client socket is closing
        ev_io_stop(loop,watcher);
        free(watcher);
        perror("peer might closing");
        total_clients --; // Decrement total_clients count
        printf("%d client(s) connected.\n", total_clients);
        return;
    } else {
        printf("message:%s\n",buffer);
    }

    // Send message bach to the client
    send(watcher->fd, buffer, read, 0);
    bzero(buffer, read);
}
