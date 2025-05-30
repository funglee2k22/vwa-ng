#include <stdio.h>      
#include <stdlib.h>     
#include <string.h>     
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>       
#include <ev.h> 


int main(int argc, char **argv)
{
    int fd;
    short port = 9443;
    if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror( "socket failed" );
        return -1;
    }

    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(9443);
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0 ) {
        perror("bind failed");
        return -1;
    }

    int enable = 1;

    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &enable, sizeof(int)) != 0) {
        perror("setsockopt(IP_TRANSPARENT) failed.");
        return -1;
    }

    if (setsockopt(fd, IPPROTO_IP, IP_RECVOPTS, &enable, sizeof(int)) < 0) { 
        perror("setsockopt IP_RECVOPTS failed.");
	return -1;
    }

    if (setsockopt(fd, SOL_IP, IP_ORIGDSTADDR, &enable, sizeof(int)) < 0) { 
        perror("setsockopt IP_ORIGDSTADDR failed.");
	return -1;
    } 

    struct iovec iov; 
    struct msghdr msg; 
    struct cmsghdr *cmsgtmp; 
    struct in_pktinfo *pktinfo; 
    char rcv_buf[4096];
    char cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];

    struct sockaddr_in srcaddr;
    struct sockaddr_in dstaddr, temp; 
    iov.iov_base = rcv_buf;
    iov.iov_len = sizeof(rcv_buf);
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    msg.msg_flags = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = &temp; 

    printf("start listening on UDP port %d\n", port);
    bzero(&srcaddr, sizeof(srcaddr));
    bzero(&dstaddr, sizeof(srcaddr));

    char buffer[4096];
    while (1) {
	int len = recvmsg(fd, &msg, MSG_OOB); 
        memcpy(&srcaddr, msg.msg_name, sizeof(srcaddr));
        int i = 0;
	for (cmsgtmp = CMSG_FIRSTHDR(&msg); cmsgtmp != NULL; cmsgtmp = CMSG_NXTHDR(&msg, cmsgtmp)) { 
            i += 1;
	    printf("iter: %d, cmsg_level: %d, cmsg_type: %d \n", i, cmsgtmp->cmsg_level, cmsgtmp->cmsg_type);
	    if (cmsgtmp->cmsg_level == SOL_IP && cmsgtmp->cmsg_type == IP_ORIGDSTADDR) { 
		printf("IP_ORIGDSTADDR is found.\n");
                struct sockaddr_in *p = (struct sockaddr_in *)CMSG_DATA(cmsgtmp); 
		memcpy(&dstaddr, p, sizeof(dstaddr));
	    }
	}

        printf("original src ip: %s:%d, -> ", inet_ntoa(srcaddr.sin_addr), ntohs(srcaddr.sin_port));
        printf("  dst ip: %s:%d  \n", inet_ntoa(dstaddr.sin_addr), ntohs(dstaddr.sin_port));
     
        //printf("inet_ntoa() must be funny. original src ip: %s:%d, -> %s:%d\n", inet_ntoa(srcaddr.sin_addr), ntohs(srcaddr.sin_port), inet_ntoa(dstaddr.sin_addr), ntohs(dstaddr.sin_port));
    }

    close(fd);
}
