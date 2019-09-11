#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <unistd.h>

#define TIMEOUT 1

#define FAKE_READ_AFL 999
#define AFL_WRITE_FAKE 998

#define FAKE_READ_TARGET 997
#define TARGET_WRITE_FAKE 996

#define AFL_READ_TARGET 995
#define TARGET_WRITE_AFL 994

#define AFL_READ_FAKE 993
#define FAKE_WRITE_AFL 992

typedef ssize_t (*orig_recv_f)(int fd, void *buf, size_t len, int flags);
typedef ssize_t (*orig_read_f)(int fd, void *buf, size_t count);

static orig_recv_f orig_recv = NULL;
static orig_read_f orig_read = NULL;

static __attribute__((constructor)) void init_method(void)
{
    orig_recv = (orig_recv_f)dlsym(RTLD_NEXT, "recv");
    orig_read = (orig_read_f)dlsym(RTLD_NEXT, "read");
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    printf("[+] READY\n");
    struct timeval tv;

    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    write(TARGET_WRITE_FAKE, "READY", 5);

    ssize_t result = orig_recv(sockfd, buf, len, flags);
    
    tv.tv_sec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    printf("RESULT: %ld\n", result);
    if (result == -1 && errno == EAGAIN) {
      printf("RESULT: %ld --- %d ---- %s\n", result, errno, strerror(errno));
      write(TARGET_WRITE_AFL, "FINISH", 6);
      printf("TIMEOUT!!!!\n");
      return 0;
    }

    printf("[+] FINISH\n");
    return result;
}
