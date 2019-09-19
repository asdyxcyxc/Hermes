#ifndef UTILITIES_H
#define UTILITIES_H

#include "state.h"
#include <sys/un.h>

void sendAll(int, unsigned char *, int);
int recvAll(int);
int new_socket(const char *, unsigned int);
int new_unix(const char *);

#endif /* UTILITIES_H */
