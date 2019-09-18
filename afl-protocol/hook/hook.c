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
#include <pthread.h>

#define FAKE_READ_TARGET 997
#define TARGET_WRITE_FAKE 996

#define AFL_READ_TARGET 995
#define TARGET_WRITE_AFL 994

#define TARGET_READ_FAKE 989
#define FAKE_WRITE_TARGET 988

typedef ssize_t (*orig_recv_f)(int fd, void *buf, size_t len, int flags);
typedef int (*orig_socket_f)(int domain, int type, int protocol);
typedef int (*orig_accept_f)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
typedef ssize_t (*orig_send_f)(int sockfd, const void *buf, size_t len, int flags);
typedef int (*orig_pthread_create_f)(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg);
typedef int (*orig_pthread_mutex_lock_f)(pthread_mutex_t *mutex);
typedef int (*orig_pthread_mutex_unlock_f)(pthread_mutex_t *mutex);
typedef unsigned int (*orig_sleep_f)(unsigned int seconds);
typedef int (*orig_pthread_detach_f)(pthread_t thread);

static orig_recv_f orig_recv = NULL;
static orig_socket_f orig_socket = NULL;
static orig_accept_f orig_accept = NULL;
static orig_send_f orig_send = NULL;
static orig_pthread_create_f orig_pthread_create = NULL;
static orig_pthread_mutex_lock_f orig_pthread_mutex_lock = NULL;
static orig_pthread_mutex_unlock_f orig_pthread_mutex_unlock = NULL;
static orig_sleep_f orig_sleep = NULL;
static orig_pthread_detach_f orig_pthread_detach = NULL;

static __attribute__((constructor)) void init_method(void)
{
  orig_recv = (orig_recv_f)dlsym(RTLD_NEXT, "recv");
  orig_socket = (orig_socket_f)dlsym(RTLD_NEXT, "socket");
  orig_accept = (orig_accept_f)dlsym(RTLD_NEXT, "accept");
  orig_send = (orig_send_f)dlsym(RTLD_NEXT, "send");
  orig_pthread_create = (orig_pthread_create_f)dlsym(RTLD_NEXT, "pthread_create");
  orig_pthread_mutex_lock = (orig_pthread_mutex_lock_f)dlsym(RTLD_NEXT, "pthread_mutex_lock");
  orig_pthread_mutex_unlock = (orig_pthread_mutex_unlock_f)dlsym(RTLD_NEXT, "pthread_mutex_unlock");
  orig_sleep = (orig_sleep_f)dlsym(RTLD_NEXT, "sleep");
  orig_pthread_detach = (orig_pthread_detach_f)dlsym(RTLD_NEXT, "pthread_detach");

}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
  ssize_t result = orig_recv(sockfd, buf, len, flags);
  if (result <= 0) {
    if (getenv("DEBUG_MODE"))
      printf("[ target %d ] Done processing\n", getpid());

    close(sockfd);
    if (getenv("USE_SIGSTOP")) {
      int tmp = kill(getpid(), SIGSTOP);
      if (getenv("DEBUG_MODE"))
        printf("[ target ] Kill myself: %d\n", tmp);
    }
    else
      kill(getpid(), SIGUSR2);
  }
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

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  int result = orig_accept(sockfd, addr, addrlen);
  pid_t pid = getpid();
  write(TARGET_WRITE_FAKE, &pid, sizeof(pid_t));
  char tmp_buf[10];
  read(TARGET_READ_FAKE, tmp_buf, sizeof(tmp_buf));

  write(TARGET_WRITE_AFL, "TIME", 4);

  if (getenv("DEBUG_MODE"))
    printf("TARGET recv: %s\n", tmp_buf);

  return result;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
  return len;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg)
{
  (*start_routine)(arg);
  return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
  return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
  return 0;
}

unsigned int sleep(unsigned int seconds)
{
  return 0;
}

int pthread_detach(pthread_t thread)
{
  return 0;
}
