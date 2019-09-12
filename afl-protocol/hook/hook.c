#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>

#define TIMEOUT_SEC 0
#define TIMEOUT_USEC 10

#define FAKE_READ_AFL 999
#define AFL_WRITE_FAKE 998

#define FAKE_READ_TARGET 997
#define TARGET_WRITE_FAKE 996

#define AFL_READ_TARGET 995
#define TARGET_WRITE_AFL 994

#define AFL_READ_FAKE 993
#define FAKE_WRITE_AFL 992

typedef ssize_t (*orig_recv_f)(int fd, void *buf, size_t len, int flags);
typedef int (*orig_socket_f)(int domain, int type, int protocol);

static orig_recv_f orig_recv = NULL;
static orig_socket_f orig_socket = NULL;

static __attribute__((constructor)) void init_method(void)
{
    orig_recv = (orig_recv_f)dlsym(RTLD_NEXT, "recv");
    orig_socket = (orig_socket_f)dlsym(RTLD_NEXT, "socket");
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
//     printf("[+] READY for recv data\n");
    struct timeval tv;

    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = TIMEOUT_USEC;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    ssize_t result = orig_recv(sockfd, buf, len, flags);
    
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
//     printf("RESULT: %ld\n", result);
    if (result == -1 && (errno == EAGAIN || errno == ECONNRESET)) {
        close(sockfd);
//       printf("RESULT: %ld --- %d ---- %s\n", result, errno, strerror(errno));
    if (getenv("USE_SIGSTOP"))
      kill(getpid(), SIGSTOP);
    else
      kill(getpid(), SIGUSR2);

//       printf("TIMEOUT!!!!\n");
      return 0;
    }

//     printf("[+] FINISH recving data\n");
    return result;
}

int socket(int domain, int type, int protocol)
{
	int result = orig_socket(domain, type, protocol);
	if (result >= 0) {
		int opt_val = 1;
		setsockopt(result, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof opt_val);
	}
	return result;
}
