#include <arpa/inet.h>
#include <signal.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include "utilities.h"
#include <errno.h>
#include <string.h>

void sendAll(int sockfd, char *msg, int len)
{
    int res;
    char *buffer = msg;
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

int send_state(thread_args *args, int *flag, pid_t frksrv, pid_t server, int done_st)
{
    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1;

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));


    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->ip_address, &(servaddr.sin_addr));

    int try = 0;

    while (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
        if ( getenv("DEBUG") )
            printf("Cannot connect to %d because (%d): %s\n", server, errno, strerror(errno));

        errno = 0;
        kill (server, 0);

        if ( getenv("DEBUG") )
            printf ("Kill null (%d / %d) : %s\n", errno, ESRCH, strerror(errno));

        if ( errno == ESRCH ) {
            close(sockfd);

            sockfd = -1;
            return 1;
        }

        usleep (try * 20);
        try ++;
    }

    if ( getenv("DEBUG") )
        puts ("CLIENT CONNECTED");

    int cnt = 0;

    messages *cur = args->state->start_msg;

    while (cur != NULL) {
        if ( getenv("DEBUG") )
            printf ("SENDING %d'th msg\n", cnt);

        if (cnt == args->state->current_msg) {
            if (args->mode == TRIM_MODE) {
                char *tmp_data = malloc(args->len);
                if (args->remove_pos)
                    memcpy(tmp_data, args->fuzz_data, args->remove_pos);
                unsigned int tail_len = args->len - args->remove_pos - args->trim_avail;
                if (args->trim_avail)
                    memcpy(tmp_data + args->remove_pos + args->trim_avail, args->fuzz_data + args->remove_pos + args->trim_avail, tail_len);
                sendAll(sockfd, tmp_data, args->remove_pos + tail_len);
            } else {
                sendAll(sockfd, args->fuzz_data, args->len);
            }
        } else 
            sendAll(sockfd, cur->data, cur->size);

        if ( cnt == args->state->current_msg ) {
            close(sockfd);
            sockfd = -1;
            int isClosed = 0;
            int tmpClosed;
            if ( getenv("DEBUG") )
                puts ("WAITING SIGNAL");
            if ( read(done_st, &isClosed, sizeof(int)) <= 0 ) {
                if ( getenv("DEBUG") )
                    printf ("Cannot recving signal from binary due to (%d): %s\n", errno, strerror(errno));
                exit(0);
            } else if ( isClosed ) {
                kill(server, SIGKILL);
                if ( read(done_st, &tmpClosed, sizeof(int)) <= 0 ) {
                    if ( getenv("DEBUG") )
                        printf ("Cannot recving signal from binary after kill due to (%d): %s\n", errno, strerror(errno));
                    exit(0);
                } 
                *flag = 1;
            }

            if ( getenv("DEBUG") )
                puts ("DONE SENDING");
            break;
        }

        cur = cur->next_msg;
        cnt ++;
    }

    return 0;
}

thread_args *createNormClient(char *ip_address, unsigned int port, protocol *state,
                      char *fuzz_data, int len)
{
    thread_args *args = malloc(sizeof (thread_args));

    args->ip_address = ip_address;
    args->port = port;
    args->state = state;
    args->fuzz_data = fuzz_data;
    args->len = len;
    args->mode = 0;

    return args;
}

thread_args *createTrimClient(char *ip_address, unsigned int port, protocol *state,
                      char *fuzz_data, int len, int remove_pos, int trim_avail)
{
    thread_args *args = malloc(sizeof (thread_args));

    args->ip_address = ip_address;
    args->port = port;
    args->state = state;
    args->fuzz_data = fuzz_data;
    args->len = len;
    args->mode = TRIM_MODE;
    args->remove_pos = remove_pos;
    args->trim_avail = trim_avail;

    return args;
}
