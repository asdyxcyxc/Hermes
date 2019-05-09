#ifndef STATE_H
#define STATE_H

#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h> 
#include <string.h>

#include "../debug.h"
#include "../config.h"
#include "../types.h"
#include "../alloc-inl.h"
#include "../hash.h"

#define NEXT_STEP 1
#define KEEP_STEP 0

#define SERVER_FIRST 1;
#define CLIENT_FIRST 0;

struct messages {
    int size;
    char *data;
    struct messages *next_msg;
};
typedef struct messages messages;

typedef struct {
    int current_msg;
    messages *start_msg, *end_msg;
    int isSkipped;
    int isAdded;
    // int who_first;
    int size;
} protocol;

typedef struct {
    int srv_pid;
    int cli_pid;
    int flag;
} share_info;

share_info *newInfo();
void setInfo_srv_pid(share_info *, int);
void setInfo_cli_pid(share_info *, int);
void enableInfo_flag(share_info *);
void deleteInfo(share_info *);

messages *newMsg(int, char *, messages *);
protocol *newProtocol(int, messages*, messages*, int, int, int);
protocol *loadFromMem(char *, int);
protocol *unserialize(char *);
void serialize(protocol *state, int cur_index, char *msg, int len, char *filename, int mode);
void deleteMsg(messages *);
void deleteProtocol(protocol *);
void debugMsg(messages *);
void debugProtocol(protocol *);
messages *getCurMsg(protocol *);
messages *getNxtMsg(protocol *);

#endif /* STATE_H */
