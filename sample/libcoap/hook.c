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
#include <sys/un.h>

#include <malloc.h>

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
typedef int (*orig_close_f)(int fd);
typedef int (*orig_bind_f)(int sockfd, const struct sockaddr *addr,
                socklen_t addrlen);
typedef int (*orig_listen_f)(int sockfd, int backlog);
typedef int (*orig_select_f)(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout);

static orig_recv_f orig_recv = NULL;
static orig_socket_f orig_socket = NULL;
static orig_accept_f orig_accept = NULL;
static orig_send_f orig_send = NULL;
static orig_pthread_create_f orig_pthread_create = NULL;
static orig_pthread_mutex_lock_f orig_pthread_mutex_lock = NULL;
static orig_pthread_mutex_unlock_f orig_pthread_mutex_unlock = NULL;
static orig_sleep_f orig_sleep = NULL;
static orig_pthread_detach_f orig_pthread_detach = NULL;
static orig_close_f orig_close = NULL;
static orig_bind_f orig_bind = NULL;
static orig_listen_f orig_listen = NULL;
static orig_select_f orig_select = NULL;

// static void my_init_hook (void);
// static void *my_malloc_hook (size_t, const void *);
// static void *my_realloc_hook (void *, size_t, const void *);
// static void my_free_hook (void*, const void *);
// 
// static void *(*old_malloc_hook)(size_t, const void *);
// static void *(*old_free_hook)(size_t, const void *);
// static void *(*old_realloc_hook)(void *, size_t, const void *);

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
  orig_close = (orig_close_f)dlsym(RTLD_NEXT, "close");
  orig_bind = (orig_bind_f)dlsym(RTLD_NEXT, "bind");
  orig_listen = (orig_listen_f)dlsym(RTLD_NEXT, "listen");
  orig_select = (orig_select_f)dlsym(RTLD_NEXT, "select");

//   old_malloc_hook = __malloc_hook;
//   old_free_hook = __free_hook;
//   old_realloc_hook = __realloc_hook;
// 
//   __malloc_hook = my_malloc_hook;
//   __free_hook = my_free_hook;
//   __realloc_hook = my_realloc_hook;
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout)
{
  if (getenv("DEBUG_MODE"))
    printf("[ target ] Going into select\n");

  int result = orig_select(nfds, readfds, writefds, exceptfds, timeout);
  if (result < 0 && getenv("DEBUG_MODE")) {
    printf("[ target ] Failed to select due to (%d): %s\n", errno, strerror(errno));
  }
  return result;
}

int listen(int sockfd, int backlog)
{
  if (getenv("DEBUG_MODE"))
    printf("[ target %d ] Going in to listen\n", sockfd);

  char *bind_dir = getenv("BIND_DIR");
  if (getenv("SHOW_SOCKFD") && bind_dir) {
    printf("[ target ] Listening on sock file: %s/sock_%d\n", bind_dir, sockfd);
  }
  return orig_listen(sockfd, backlog);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  char *bind_dir = getenv("BIND_DIR");
  if (bind_dir) {
    char *new_sock = malloc(strlen(bind_dir) + 6 + 10);
    snprintf(new_sock, strlen(bind_dir) + 6 + 10, "%s/sock_%d", bind_dir, sockfd);
    unlink(new_sock);
    if (getenv("DEBUG_MODE"))
      printf("[ target ] Sockfile: %s\n", new_sock);
    struct sockaddr_un un_addr;
    memset(&un_addr, 0, sizeof(un_addr));
    un_addr.sun_family = AF_UNIX;
    strncpy(un_addr.sun_path, new_sock, sizeof(un_addr.sun_path)-1);
    free(new_sock);
    return orig_bind(sockfd, (struct sockaddr*)&un_addr, addrlen);
  } else {
    if (getenv("DEBUG_MODE"))
      printf("[ target ] Going in to normal bind for fd: %d\n", sockfd);
    return orig_bind(sockfd, addr, addrlen);
  }
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
  if (getenv("DEBUG_MODE"))
    printf("[ target ] Recv on sockfd: %d\n", sockfd);
  
  ssize_t result = orig_recv(sockfd, buf, len, flags);
  return result;
}

int close(int fd)
{
  if (getenv("DEBUG_MODE"))
    printf("[ target ] Close fd: %d\n", fd);

  return orig_close(fd);
}

int socket(int domain, int type, int protocol)
{
  int result;
  result = orig_socket(domain, type, protocol);
  
  if (getenv("DEBUG_MODE"))
    printf("[ target ] Socket created: %d\n", result);

  return result;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  if (getenv("DEBUG_MODE"))
    printf("[ target ] Going into accept()\n");

  int result = orig_accept(sockfd, addr, addrlen);
  return result;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
  if (getenv("DEBUG_MODE"))
    printf("[ target ] Going into send()\n");

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

// static void *my_malloc_hook (size_t size, const void *caller)
// {
//   void *result;
//   __malloc_hook = old_malloc_hook;
//   __free_hook = old_free_hook;
//   __realloc_hook = old_realloc_hook;
// 
//   result = malloc (size);
//   old_malloc_hook = __malloc_hook;
//   old_free_hook = __free_hook;
//   old_realloc_hook = __realloc_hook;
// 
//   if (getenv("DEBUG_MALLOC"))
//     printf ("[ ===== target ===== ] malloc(%u) = %p\n", (unsigned int) size, result);
//   __malloc_hook = my_malloc_hook;
//   __free_hook = my_free_hook;
//   __realloc_hook = my_realloc_hook;
//   return result;
// }
// 
// static void my_free_hook (void *ptr, const void *caller)
// {
//   __malloc_hook = old_malloc_hook;
//   __free_hook = old_free_hook;
//   __realloc_hook = old_realloc_hook;
// 
//   free (ptr);
//   old_malloc_hook = __malloc_hook;
//   old_free_hook = __free_hook;
//   old_realloc_hook = __realloc_hook;
// 
//   if (getenv("DEBUG_FREE"))
//     printf ("[ ===== target ===== ] free(%p)\n", ptr);
//   __malloc_hook = my_malloc_hook;
//   __free_hook = my_free_hook;
//   __realloc_hook = my_realloc_hook;
// }
// 
// static void *my_realloc_hook (void *ptr, size_t size, const void *caller)
// {
//   void *result;
//   __malloc_hook = old_malloc_hook;
//   __free_hook = old_free_hook;
//   __realloc_hook = old_realloc_hook;
// 
//   result = realloc (ptr, size);
//   old_malloc_hook = __malloc_hook;
//   old_free_hook = __free_hook;
//   old_realloc_hook = __realloc_hook;
// 
//   if (getenv("DEBUG_REALLOC"))
//     printf ("[ ===== target ===== ] realloc(%p, %u) = %p\n", ptr, (unsigned int) size, result);
//   
//   __malloc_hook = my_malloc_hook;
//   __free_hook = my_free_hook;
//   __realloc_hook = my_realloc_hook;
// 
//   return result;
// }
