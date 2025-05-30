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
    serveraddr.sin_port = htons(port);
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0 ) {
        perror("bind failed");
        return -1;
    }

    int enable = 1;
#if 0
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &enable, sizeof(enable)) < 0) { 
        perror("setsockopt IP_PKTINFO failed.");
	return -1;
    }
#endif 

    if (setsockopt(fd, IPPROTO_IP, IP_RECVORIGDSTADDR, &enable, sizeof(enable)) < 0) { 
        perror("setsockopt IP_RECVORIGDST failed.");
	return -1;
    } 


    struct iovec iov; 
    struct msghdr msg; 
    struct cmsghdr *cmsgtmp; 
    struct in_pktinfo *pktinfo; 
    char rcv_buf[4096];
    char cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];

    struct sockaddr_in srcaddr;
    struct sockaddr_in dstaddr; 
    iov.iov_base = rcv_buf;
    iov.iov_len = sizeof(rcv_buf);
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    msg.msg_flags = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = &srcaddr; 

    printf("start listening on UDP port %d\n", port);

    char buffer[4096];
    while (1) {
	int len = recvmsg(fd, &msg, 0); 
        //store the source address first.
	//memcpy(&srcaddr, msg.msg_name, sizeof(srcaddr));
	for (cmsgtmp = CMSG_FIRSTHDR(&msg); cmsgtmp != NULL; cmsgtmp = CMSG_NXTHDR(&msg, cmsgtmp)) { 
	    if (cmsgtmp->cmsg_level == SOL_IP && cmsgtmp->cmsg_type == IP_ORIGDSTADDR) { 
                struct sockaddr_in *p = (struct sockaddr_in *)CMSG_DATA(cmsgtmp); 
		memcpy(&dstaddr, p, sizeof(dstaddr));
		printf("original dst ip: %s:%d  \n", inet_ntoa(p->sin_addr), ntohs(p->sin_port));
		break;
	    }
	}
     
    }

    close(fd);
}
