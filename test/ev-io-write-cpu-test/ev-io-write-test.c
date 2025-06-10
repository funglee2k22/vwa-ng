#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 5201

ev_io *client_write_watcher; 
char buffer[1024];

static void client_cb(EV_P_ ev_io *w, int revents) {

    ssize_t bytes_read;
    int client_fd = w->fd;

    if (revents & EV_READ) {
        bytes_read = read(client_fd, buffer, sizeof(buffer));
        if (bytes_read > 0) {
            //write(client_fd, buffer, bytes_read); // Echo back
            ev_feed_event(EV_A_ client_write_watcher, EV_WRITE);
        } else if (bytes_read == 0) {
            printf("Client disconnected.\n");
            ev_io_stop(EV_A_ w);
            close(client_fd);
            free(w);
        } else {
            perror("read");
            ev_io_stop(EV_A_ w);
            close(client_fd);
            free(w);
        }
    }
}

static void client_write_cb(EV_P_ ev_io *w, int revents) {
    char *message = "Received OK.\n"; 
    char outbuf[2056] = {0};
    sprintf(outbuf, "%s %s\n", buffer, message);
    ssize_t bytes_sent = write(w->fd, outbuf, sizeof(outbuf)); 
    if (bytes_sent < 0) { 
         perror("write");
         ev_io_stop(EV_A_ w);
         close(w->fd);
         free(w);
    }

} 


static void accept_cb(EV_P_ ev_io *w, int revents) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int server_fd = w->fd;

    if (revents & EV_READ) {
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            return;
        }
        printf("New client connected.\n");

        ev_io *client_watcher = (ev_io *)malloc(sizeof(ev_io));
        ev_io_init(client_watcher, client_cb, client_fd, EV_READ);
        ev_io_start(EV_A_ client_watcher);

        client_write_watcher = (ev_io *)malloc(sizeof(ev_io));
        ev_io_init(client_write_watcher, client_write_cb, client_fd, EV_WRITE);
    }
}

int main() {
    struct ev_loop *loop = EV_DEFAULT;
    int server_fd;
    struct sockaddr_in server_addr;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        return 1;
    }

    ev_io server_watcher;
    ev_io_init(&server_watcher, accept_cb, server_fd, EV_READ);
    ev_io_start(loop, &server_watcher);

    printf("Server listening on port %d...\n", PORT);
    ev_run(loop, 0);

    close(server_fd);
    return 0;
}
