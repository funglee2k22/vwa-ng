/**
 * tuntap_forwarder.c
 *
 * This program is a C version of the C++ forwarder. It demonstrates how to
 * use a TUN interface to intercept, inspect, and forward UDP packets.
 *
 * 1. Opens a TUN device specified by the user.
 * 2. Creates a raw socket for sending packets back out.
 * 3. Enters a loop to read IP packets from the TUN device.
 * 4. For each packet, it checks if it's UDP.
 * 5. If it's UDP, it prints the source/destination IPs and ports.
 * 6. It then forwards the original packet using the raw socket.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

// Helper function to create a TUN device and return its file descriptor
int tun_alloc(const char *dev) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // IFF_TUN for L3, IFF_NO_PI for no extra packet info
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1); // IFNAMSIZ-1 to be safe
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    return fd;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <tun_interface_name>\n", argv[0]);
        return 1;
    }

    const char *tun_name = argv[1];

    // 1. Create the TUN interface
    int tun_fd = tun_alloc(tun_name);
    if (tun_fd < 0) {
        fprintf(stderr, "Failed to create TUN device.\n");
        return 1;
    }
    printf("Successfully created TUN device '%s'.\n", tun_name);

    // 2. Create a raw socket for sending packets back out
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        perror("socket(AF_INET, SOCK_RAW)");
        close(tun_fd);
        return 1;
    }

    // Tell the kernel that we will provide the IP header ourselves
    int on = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(tun_fd);
        close(raw_sock);
        return 1;
    }
    printf("Raw socket for forwarding created successfully.\n");

    // 3. Main loop to read from TUN and write to raw socket
    char buffer[2048];
    while (1) {
        ssize_t nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            perror("read from TUN");
            close(tun_fd);
            close(raw_sock);
            return 1;
        }

        // --- INSPECTION LOGIC ---
        // The buffer now contains a full IP packet
        struct iphdr *ip_header = (struct iphdr *)buffer;

        // Check if the packet is UDP
        if (ip_header->protocol == IPPROTO_UDP) {
            // The UDP header starts after the IP header.
            // The IP header length is in 32-bit words, so multiply by 4.
            struct udphdr *udp_header = (struct udphdr *)(buffer + ip_header->ihl * 4);

            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_header->saddr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &ip_header->daddr, dst_ip, sizeof(dst_ip));

            printf("Intercepted UDP Packet: %s:%u -> %s:%u | Length: %u\n",
                   src_ip, ntohs(udp_header->source),
                   dst_ip, ntohs(udp_header->dest),
                   ntohs(udp_header->len));

            // Here you could modify the packet buffer if needed
        }

#if 0
	/* Modify the packet and send through another interface 
	 * Note: Code is missing here for any modifications, edit it as you wish
	 */
        // --- FORWARDING LOGIC ---
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_addr.s_addr = ip_header->daddr;

        ssize_t nwrite = sendto(raw_sock, buffer, nread, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (nwrite < 0) {
            perror("sendto raw socket");
            // Decide if you want to exit on send error
        }
#endif
    }

    close(tun_fd);
    close(raw_sock);
    return 0;
}
