CFLAGS=-O3 -funroll-loops -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign

AFL_PATH = \"/usr/local/lib/afl\"
DOC_PATH = \"/usr/local/share/doc/afl\"
BIN_PATH = \"/usr/local/bin\"

LDFLAGS = -ldl

COMM_HEADER = helper/alloc-inl.h helper/config.h helper/debug.h helper/types.h

all: afl-fuzz interceptor libhook

afl-fuzz: afl-fuzz.c $(COMM_HEADER)
	$(CC) $(CFLAGS) -DAFL_PATH=$(AFL_PATH) -DDOC_PATH=$(DOC_PATH) -DBIN_PATH=$(BIN_PATH) $@.c network/*.c -o $@ $(LDFLAGS) $(INCLUDE) 

interceptor: interceptor.c $(COMM_HEADER)
	$(CC) -g $@.c network/state.c network/utilities.c -o $@ -lpcap

libhook: hook/hook.c
	$(CC) -c -fpic hook/hook.c -ldl
	$(CC) -shared -o libhook.so hook.o -ldl
	rm hook.o

clean:
	rm -f afl-fuzz interceptor
	rm -f libhook.so
