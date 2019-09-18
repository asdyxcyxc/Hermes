#ifndef STATE_H
#define STATE_H

#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h> 
#include <string.h>
#include <ctype.h>
#include <signal.h>

#include "../helper/debug.h"
#include "../helper/config.h"
#include "../helper/types.h"
#include "../helper/alloc-inl.h"
#include "../helper/hash.h"

#include "utilities.h"

#define FAKE_READ_TARGET 997
#define TARGET_WRITE_FAKE 996

#define AFL_READ_TARGET 995
#define TARGET_WRITE_AFL 994

#define TARGET_READ_FAKE 989
#define FAKE_WRITE_TARGET 988

struct messages {
    int size;
    char *data;
    int done_det;
    int done_trim;
    struct messages *next_msg;
};
typedef struct messages messages;

typedef struct {
    int current_msg;
    messages *start_msg, *end_msg;
    unsigned long long int done_det_mask; // Currently limit the number of msgs by 64
    unsigned long long int done_trim_mask;
    int size;
} protocol;

messages *newMsg(int, char *, messages *, int, int);
protocol *newProtocol(int, messages*, messages*, int);
protocol *loadFromMem(char *, int);
protocol *unserialize(char *);
int getLenUntil(protocol *, int);
unsigned char *dump_fuzzed_data(protocol *, unsigned char *, unsigned int, int *);
unsigned char *dump_data(protocol *, int *);
void serialize(protocol *, int, char *, int, char *);
void deleteMsg(messages *);
void deleteProtocol(protocol *);
void debugMsg(messages *);
void debugProtocol(protocol *);
void pprint(const char *, char *, int);
messages *getCurMsg(protocol *);
messages *getNxtMsg(protocol *);
messages *getMsg(protocol *, int);
void setup_communications(unsigned int *, const char *, uint16_t, unsigned char *, unsigned char *);

#endif /* STATE_H */
