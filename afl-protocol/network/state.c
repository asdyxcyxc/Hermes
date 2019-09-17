#include "state.h"

messages *newMsg(int size, char *data, messages *prev, int done_det, int done_trim)
{
    messages *result = calloc(1, sizeof(messages));
    result->size = size;
    result->data = data;
    result->done_det = done_det;
    result->done_trim = done_trim;
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
    result->done_det_mask = 0;
    result->done_trim_mask = 0;

    messages *cur = result->start_msg;
    while (cur != NULL) {
        result->done_det_mask |= cur->done_det;
        result->done_trim_mask |= cur->done_trim;
        cur = cur->next_msg;
    }
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
    while (cur != NULL && cnt != state->current_msg + 1) {
        cnt ++;
        cur = cur->next_msg;
    }
    return cur;
}

messages *getMsg(protocol *state, int index)
{
    int cnt = 0;
    messages *cur = state->start_msg;
    while (cur != NULL && cnt != index) {
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

        int done_det;
        memcpy(&done_det, tmp_buf + pos, sizeof(int));
        pos += sizeof(int);

        int done_trim;
        memcpy(&done_trim, tmp_buf + pos, sizeof(int));
        pos += sizeof(int);

        char *buf = malloc(size);
        memcpy(buf, tmp_buf + pos, size);
        pos += size;

        if (start == NULL) {
            start = newMsg(size, buf, NULL, done_det, done_trim);
            prev_obj = start;
        } else {
            messages *tmp_msg = newMsg(size, buf, prev_obj, done_det, done_trim);
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
            ck_write(fd, &cur->done_det, sizeof(int), filename);
            ck_write(fd, &cur->done_trim, sizeof(int), filename);
            ck_write(fd, msg, len, filename);
        } else {
            ck_write(fd, &cur->size, sizeof(int), filename);
            ck_write(fd, &cur->done_det, sizeof(int), filename);
            ck_write(fd, &cur->done_trim, sizeof(int), filename);
            ck_write(fd, cur->data, cur->size, filename);
        }
        cur = cur->next_msg;
        cnt++;
    }

    close(fd);
}

int getLenUntil(protocol *state, int index)
{
    int result = 0, cnt = 0;
    messages *cur = state->start_msg;
    
    while (cur != NULL && cnt != index) {
        result += cur->size;
        cur = cur->next_msg;
        cnt ++;
    }
    return result;
}

unsigned char *dump_data(protocol *state, int *len)
{
    unsigned char *result = NULL;
    messages *cur = state->start_msg;
    int total_size = 0;

    while (cur != NULL) {
        result = ck_realloc(result, total_size + cur->size);
        memcpy(result + total_size, cur->data, cur->size);
        total_size += cur->size;
        cur = cur->next_msg;
    }

    *len = total_size;
    return result;
}

unsigned char *dump_fuzzed_data(protocol *state, unsigned char *data, unsigned int len, int *length)
{
    unsigned char *result = NULL;
    messages *cur = state->start_msg;
    int total_size = 0;
    int cnt = 0;

    while (cur != NULL) {
        if (cnt == state->current_msg) {
            result = ck_realloc(result, total_size + len);
            memcpy(result + total_size, data, len);
        } else {
            result = ck_realloc(result, total_size + cur->size);
            memcpy(result + total_size, cur->data, cur->size);
        }
        total_size += cur->size;
        cnt ++;
        cur = cur->next_msg;
    }

    *length = total_size;
    return result;
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

    int cnt = 0;
    messages *cur = obj->start_msg;
    while (cur != NULL) {
        SAYF("\t" cLRD "[-] " cRST
                "Message %d:\n", cnt++);
        debugMsg(cur);
        cur = cur->next_msg;
    }
}

void pprint(const char *prefix, char *s, int size)
{
    if (getenv("DEBUG_MODE")) {
        printf("[+] %s (%d): ", prefix, size);
        int i=0;
        for (i=0; i<size; ++i)
            if (isprint(s[i]))
                printf("%c", (char)s[i]);
            else
                printf("\\x%x", ((char)s[i]) & 0xff);
        printf("\n");
    }
}

void setup_communications(u32 *client_fd, const char *out_file, u16 port, u8 *trace_bits, u8 *new_prev_loc)
{
    pid_t cfd;
    s32 pipe_target_fake[2], pipe_fake_target[2];
    char tmp_buf[10];

    ACTF("Making pipes ...");

    if (pipe(pipe_target_fake) || pipe(pipe_fake_target))
        PFATAL("pipe() for setup communications failed");
    cfd = fork();

    if (cfd < 0) PFATAL("fork() fake client failed");

    if (!cfd) {
        s32 sockfd = 1337;
        /* FAKE CLIENT */
        if (dup2(pipe_target_fake[0], FAKE_READ_TARGET) < 0)
            PFATAL("dup2() for read from target to client failed");
        if (dup2(pipe_fake_target[1], FAKE_WRITE_TARGET) < 0)
            PFATAL("dup2() for write from fake to target failed");

        close(pipe_target_fake[0]);
        close(pipe_target_fake[1]);
        close(pipe_fake_target[0]);
        close(pipe_fake_target[1]);

        while (1) {
            sockfd = new_connection("127.0.0.1", port);
            
            int child_pid;
            read(FAKE_READ_TARGET, &child_pid, sizeof(int));

            if (getenv("DEBUG_MODE")) {
                printf("[+] Client recv child_pid: %d\n", child_pid);
                printf("[************* DEBUG BEOFRE RESET *************]\n");
                u32 i;

                for (i=0; i<MAP_SIZE; ++i)
                    if (trace_bits[i])
                        printf("[---] 0x%x: trace bit %d\n", i, trace_bits[i]);
                printf("[++++] Final prev: %llu\n", *(u64 *)new_prev_loc);
                printf("[*********************************]\n");
            }

            memset(trace_bits, 0, MAP_SIZE);
            memset(new_prev_loc, 0, sizeof(u64));

            write(FAKE_WRITE_TARGET, "DONE", 4);

            if (sockfd < 0) PFATAL("Cannot connect to target");

            if (getenv("DEBUG_MODE"))
                printf("[+] Client has been connected\n");


            s32 fd = open(out_file, O_RDONLY);
            if (fd < 0) PFATAL("Unable to open %s", out_file);
            u32 size = lseek(fd, 0, SEEK_END);
            u8 *buffer = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
            close(fd);

            if (getenv("DEBUG_MODE"))
                pprint("CLIENT", (char *)buffer, size);
            sendAll(sockfd, buffer, size);
            munmap(buffer, size);

            close(sockfd);
        }
        exit(0);
    } else {
        if (dup2(pipe_target_fake[1], TARGET_WRITE_FAKE) < 0)
            PFATAL("dup2() for write from target to client failed");
        if (dup2(pipe_fake_target[0], TARGET_READ_FAKE) < 0)
            PFATAL("dup2() for read from fake to target failed");

        close(pipe_target_fake[0]);
        close(pipe_target_fake[1]);
        close(pipe_fake_target[0]);
        close(pipe_fake_target[1]);

        *client_fd = cfd;
    }
}
