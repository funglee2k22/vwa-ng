#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int tun_alloc(char *dev, int flags) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

void set_ip_and_up(char *dev_name, const char *ip_addr_str, const char *netmask_str) {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);

    // Set IP address
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip_addr_str, &addr->sin_addr);
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl SIOCSIFADDR");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Set Netmask
    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, netmask_str, &addr->sin_addr);
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCSIFNETMASK");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Bring interface UP
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    close(sockfd);
}

int main() {
    char tun_name[IFNAMSIZ] = "tun0"; // Desired TUN device name
    int tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI); // IFF_NO_PI for raw IP packets

    if (tun_fd < 0) {
        fprintf(stderr, "Failed to create TUN device\n");
        return 1;
    }
    printf("TUN device %s created successfully.\n", tun_name);

    set_ip_and_up(tun_name, "192.168.10.102", "255.255.255.0");
    printf("IP address assigned and interface brought up.\n");
    while (1) { 
        char buf[4096];
        ssize_t nbytes = read(tun_fd, buf, sizeof(buf));
        printf("Read %ld bytes from tun0\n", nbytes);

    }
    // At this point, you can read/write IP packets from/to tun_fd
    // For a real application, you'd typically enter a loop to handle traffic.

    // Close the TUN device when done (e.g., on program exit)
    // close(tun_fd); 
    return 0;
}
