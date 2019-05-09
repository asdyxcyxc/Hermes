#ifndef UTILITIES_H
#define UTILITIES_H

#include "state.h"

#define TRIM_MODE 1

typedef struct {
    char *ip_address;
    unsigned int port;
    protocol *state;
    char *fuzz_data;
    int len;
    int mode;
    unsigned int remove_pos;
    unsigned int trim_avail;
} thread_args;

void sendAll(int, char *, int);
int send_state(thread_args *args, int *flag, pid_t frksrv, pid_t server, int done_st);

thread_args *createNormClient(char *ip_address, unsigned int port, protocol *state,
                      char *fuzz_data, int len);

thread_args *createTrimClient(char *ip_address, unsigned int port, protocol *state,
                      char *fuzz_data, int len, int remove_pos, int
                      trim_avail);

#endif /* UTILITIES_H */
