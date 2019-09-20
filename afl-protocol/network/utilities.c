#include <arpa/inet.h>
#include <signal.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include "utilities.h"
#include <errno.h>
#include <string.h>

void sendAll(int sockfd, unsigned char *msg, int len)
{
    int res;
    unsigned char *buffer = msg;
    int tmp_len = len;

    while (1) {
        res = send(sockfd, buffer, tmp_len, 0);
        if ( res < 0 ) {
          if (getenv("DEBUG_MODE"))
            printf("[ client ] Failed to send data due to (%d): %s\n", errno, strerror(errno));
          return;
        }
        else {
            if ( res == tmp_len )
                break;
            else {
                buffer += res;
                tmp_len -= res;
            }
        }

    }
}

int recvAll(int sockfd) {
    char tmp_buf[100] = {0};
    int timeRecv = 0;

    while (1) {
        int res = recv(sockfd, tmp_buf, 99, 0);
        printf("[ client ] Recv: %s\n", tmp_buf);
        if ( res <= 0 ) {
            if ( timeRecv )
                return 0;
            else
                return 1;
        }
        else {
            timeRecv ++;
        }
    }

}

int new_socket(const char *ip, unsigned int port)
{
    int sockfd;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
	int opt_val = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof opt_val);

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr)); 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = inet_addr(ip); 
    servaddr.sin_port = htons(port); 

    while (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
        if (getenv("DEBUG_MODE")) {
            printf("[ fake ] Cannot connect to socket due to (%d): %s\n", errno, strerror(errno));
            sleep(1);
        }
    }
    return sockfd;
}

int new_unix(const char *sockfile)
{
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un un_addr;
    memset(&un_addr, 0, sizeof(un_addr));
    un_addr.sun_family = AF_UNIX;
    strncpy(un_addr.sun_path, sockfile, sizeof(un_addr.sun_path)-1);

    while (connect(sockfd, (struct sockaddr *)&un_addr, sizeof(un_addr)) != 0) {
        if (getenv("DEBUG_MODE")) {
            printf("[ client ] Cannot connect to unix sock due to (%d): %s\n", errno, strerror(errno));
            sleep(1);
        }
    }

    return sockfd;
}
