#define _GNU_SOURCE
#include <dlfcn.h>
 
#include <sys/types.h>
#include <sys/socket.h>

#include "network.h"

typedef int (*orig_socket_f)(int domain, int type, int protocol);
typedef int (*orig_recv_f)(int fd, void *buf, size_t len, int flags);

static orig_socket_f orig_socket = NULL;
static orig_recv_f orig_recv = NULL;

// patched socket function to enable SO_REUSEADDR option,
// so we can reuse socket quickly after close it
int socket(int domain, int type, int protocol)
{
	puts ("PATCHED SOCKET!!!");
	int result = orig_socket(domain, type, protocol);
	if (result >= 0) {
		int opt_val = 1;
		// syscall(SYS_setsockopt, result, 1, 2, &opt_val, sizeof(opt_val));
		setsockopt(result, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof opt_val);
	}
	return result;
}

// patched recv function for injecting ending signal
// so AFL will shutdown target if it finishes a session
ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t result;

	puts("PATCHED RECV!!!");
	result = orig_recv(fd, buf, len, flags);
	if (result <= 0) {
		int tmp_result, isClosed = 1;

		printf ("SENDING SIGNAL FROM %d\n", getpid());

		tmp_result = write(FORKSRV_FD + 2, &isClosed, sizeof(int));
		if (tmp_result <= 0) {
			printf ("ERROR WHILE SENDING SIGNAL (%d): %s\n", errno, strerror(errno));
		}
		// done with input processing, lets kill the target now
		exit(0);

		// put target into sleep
		// kill(getpid(), SIGSTOP);
	}

	return result;
}

static __attribute__((constructor)) void init_method(void)
{
    orig_socket = (orig_socket_f)dlsym(RTLD_NEXT, "socket");
    orig_recv = (orig_recv_f)dlsym(RTLD_NEXT, "recv");
}
