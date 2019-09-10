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
        if ( res < 0 )
            PFATAL("Error while sending to socket");
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

int new_connection(const char *ip, unsigned int port)
{
    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&servaddr, sizeof(servaddr)); 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = inet_addr(ip); 
    servaddr.sin_port = htons(port); 
    
    while (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0);
    return sockfd;
}
