#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

int tun_open(char* devname) {
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

int process_pkts(char *buf, struct sockaddr_in *src, struct sockaddr_in *dst)
{
    struct iphdr *iph = (struct iphdr *)buf;
        
    if (iph->protocol != IPPROTO_UDP) { 
         printf("iph protocol %u, ntohs %u.\n", iph->protocol, ntohs(iph->protocol));
         return -1;
    } 

    struct udphdr *udph = (struct udphdr *)(buf + iph->ihl * 4);

    src->sin_family = AF_INET;
    src->sin_addr.s_addr = iph->saddr;
    src->sin_port = udph->source;

    dst->sin_family = AF_INET;
    dst->sin_addr.s_addr = iph->daddr;
    dst->sin_port = udph->dest;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src->sin_addr.s_addr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst->sin_addr.s_addr, dst_ip, sizeof(dst_ip));

    printf("received UDP packet from %s:%u to %s:%u, udp_len: %u \n",
           src_ip, ntohs(src->sin_port), dst_ip, ntohs(dst->sin_port), ntohs(udph->len));

    return ntohs(udph->len);
}


int main(int argc, char* argv[]) {
    int fd, nbytes;
    char buf[1600];
    fd = tun_open("tun0");
    printf("Device tun0 opened with fd %d\n", fd);
    struct sockaddr_in src, dst;
    while (1) {
        nbytes = read(fd, buf, sizeof(buf));
        printf("Read %d bytes from tun0\n", nbytes);
        int udp_pay_load = process_pkts(buf, &src, &dst);
    }
    return 0;
}
