#include "state.h"

messages *newMsg(int size, char *data, messages *prev)
{
    messages *result = calloc(1, sizeof(messages));
    result->size = size;
    result->data = data;
    result->next_msg = NULL;
    if (prev != NULL)
        prev->next_msg = result;
    return result;
}

protocol *newProtocol(int current_msg, messages *start_msg, messages *end_msg, int size)
{
    protocol *result = calloc(1, sizeof(protocol));
    result->current_msg = current_msg;
    result->start_msg = start_msg;
    result->end_msg = end_msg;
    result->size = size;
    return result;
}

void deleteMsg(messages *obj)
{
    memset(obj->data, 0, obj->size);
    free(obj->data);
    memset(obj, 0, sizeof(messages));
    free(obj);
}

void deleteProtocol(protocol *obj)
{
    messages *cur = obj->start_msg;
    while (cur != NULL) {
        messages *tmp = cur->next_msg;
        deleteMsg(cur);
        cur = tmp;
    }
    memset(obj, 0, sizeof(protocol));
    free(obj);
}

messages *getCurMsg(protocol *state)
{
    int cnt = 0;
    messages *cur = state->start_msg;
    while (cur != NULL && cnt != state->current_msg) {
        cnt++;
        cur = cur->next_msg;
    }
    return cur;
}

messages *getNxtMsg(protocol *state)
{
    int cnt = 0;
    messages *cur = state->start_msg;
    while ( cur != NULL && cnt != state->current_msg + 1 ) {
        cnt ++;
        cur = cur->next_msg;
    }
    return cur;
}

protocol *loadFromMem(char *tmp_buf, int totalSize)
{
    long pos = 0;
    messages *start = NULL;
    messages *prev_obj = NULL;

    int current_msg;
    memcpy(&current_msg, tmp_buf + pos, sizeof(int));
    pos += sizeof(int);
    int cnt = 0;

    while (pos < totalSize) {
        int size;
        memcpy(&size, tmp_buf + pos, sizeof(int));
        pos += sizeof(int);

        char *buf = malloc(size);
        memcpy(buf, tmp_buf + pos, size);
        pos += size;

        if (start == NULL) {
            start = newMsg(size, buf, NULL);
            prev_obj = start;
        } else {
            messages *tmp_msg = newMsg(size, buf, prev_obj);
            prev_obj = tmp_msg;
        }
        cnt++;
    }

    return newProtocol(current_msg, start, prev_obj, cnt);
}

protocol *unserialize(char *filename)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", filename);

    long totalSize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    char *tmp_buf = mmap(0, totalSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (tmp_buf == MAP_FAILED) PFATAL("Unable to load state from '%s'", filename);

    close(fd);
    protocol *result = loadFromMem(tmp_buf, totalSize);
    munmap(tmp_buf, totalSize);
    return result;
}

void serialize(protocol *state, int cur_index, char *msg, int len, char *filename)
{
    int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to save state into '%s'", filename);

    ck_write(fd, &cur_index, sizeof(int), filename);

    messages *cur = state->start_msg;
    int cnt = 0;
    while (cur != NULL) {
        if (cnt == cur_index) {
            ck_write(fd, &len, sizeof(int), filename);
            ck_write(fd, msg, len, filename);
        } else {
            ck_write(fd, &cur->size, sizeof(int), filename);
            ck_write(fd, cur->data, cur->size, filename);
        }
        cur = cur->next_msg;
        cnt++;
    }

    close(fd);
}

void debugMsg(messages *obj)
{
    SAYF("\t\t" cLRD "[+] " cRST
            "Size: %d\n", obj->size);

    SAYF("\t\t" cLRD "[+] " cRST
            "Content: ");

    int i=0;
    for (i=0; i<obj->size; ++i)
        if (isprint(obj->data[i]))
            printf("%c", (char)obj->data[i]);
        else
            printf("\\x%x", ((char)obj->data[i]) & 0xff);

    printf("\n");
}

void debugProtocol(protocol *obj)
{
    SAYF("\n" cLRD "[*] " cRST
            "The state of protocol:\n");

    SAYF("\t\t" cLRD "[+] " cRST
            "Size of protocol: %d\n", obj->size);

    SAYF("\t\t" cLRD "[+] " cRST
            "Current index: %d\n", obj->current_msg);

    SAYF("\t\t" cLRD "[+] " cRST
            "isSkipped: %d\n", obj->isSkipped);

    SAYF("\t\t" cLRD "[+] " cRST
            "isAdded: %d\n", obj->isAdded);

    int cnt = 0;
    messages *cur = obj->start_msg;
    while (cur != NULL) {
        SAYF("\t" cLRD "[-] " cRST
                "Message %d:\n", cnt++);
        debugMsg(cur);
        cur = cur->next_msg;
    }
}
