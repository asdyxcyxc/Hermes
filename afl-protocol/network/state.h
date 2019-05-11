#ifndef STATE_H
#define STATE_H

#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h> 
#include <string.h>
#include <ctype.h>

#include "../helper/debug.h"
#include "../helper/config.h"
#include "../helper/types.h"
#include "../helper/alloc-inl.h"
#include "../helper/hash.h"

struct messages {
    int size;
    char *data;
    struct messages *next_msg;
};
typedef struct messages messages;

typedef struct {
    int current_msg;
    messages *start_msg, *end_msg;
    int size;
} protocol;

messages *newMsg(int, char *, messages *);
protocol *newProtocol(int, messages*, messages*, int);
protocol *loadFromMem(char *, int);
protocol *unserialize(char *);
void serialize(protocol *, int, char *, int, char *);
void deleteMsg(messages *);
void deleteProtocol(protocol *);
void debugMsg(messages *);
void debugProtocol(protocol *);
messages *getCurMsg(protocol *);
messages *getNxtMsg(protocol *);

#endif /* STATE_H */
