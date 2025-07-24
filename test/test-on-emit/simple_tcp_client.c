#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define PORT 5203

int main()
{
	int sockfd;
	struct sockaddr_in servaddr;

	// socket create and varification
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		printf("socket creation failed...\n");
		exit(0);
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	servaddr.sin_port = htons(PORT);

	// connect the client socket to server socket
	if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
		printf("connection with the server failed...\n");
		exit(0);
	} else{
		printf("connected to the server..\n");
	}

	char buf[1024];
    ssize_t target_size = 1024 * 3, total_sent_size = 0, sent_size = 0; 
    int i = 0; 
    
    do { 
         memset(buf, 'a' + i, sizeof(buf)); 
         sent_size = write(sockfd, buf, sizeof(buf)); 
         if (sent_size <= 0) 
              break;    
         total_sent_size += sent_size; 
         printf("sent#%d, \"%.*s\" \n", i, (int) sent_size, buf);
         i += 1; 
         sleep(5);
    } while (total_sent_size < target_size); 
         
    printf("total sent %ld bytes\n", total_sent_size);
	
	close(sockfd);
}
