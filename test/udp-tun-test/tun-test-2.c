#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

int main(int argc, char **argv)
{
    int n;
    int ret = 0;
    int sock;
    char buf[2048];
    struct ifreq ifreq;
    struct sockaddr_ll saddr;

    // create socket
    if((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        ret = errno;
        goto error_exit;
    }

    // bind tap0
    snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "tun0");
    if (ioctl(sock, SIOCGIFINDEX, &ifreq)) {
        ret = errno;
        goto error_exit;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = ifreq.ifr_ifindex;
    saddr.sll_pkttype = PACKET_HOST;

    if(bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        ret = errno;
        goto error_exit;
    }

    // recv data
    while(1) {
        n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
        printf("%d bytes recieved\n", n);
    }

error_exit:
    if (ret) {
        printf("error: %s (%d)\n", strerror(ret), ret);
    }
    close(sock);
    return ret;
}
