#ifndef UTILITIES_H
#define UTILITIES_H

#include "state.h"
#include <sys/un.h>

void sendAll(int, unsigned char *, int);
int recvAll(int);
int new_connection(const char *, unsigned int);

#endif /* UTILITIES_H */
