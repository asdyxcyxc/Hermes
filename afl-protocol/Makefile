CFLAGS=-O3 -funroll-loops -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign

AFL_PATH = \"/usr/local/lib/afl\"
DOC_PATH = \"/usr/local/share/doc/afl\"
BIN_PATH = \"/usr/local/bin\"

LDFLAGS = -ldl

COMM_HEADER = helper/alloc-inl.h helper/config.h helper/debug.h helper/types.h

all: afl-fuzz interceptor lib afl-protocol

afl-fuzz: afl-fuzz.c $(COMM_HEADER)
	$(CC) $(CFLAGS) -DAFL_PATH=$(AFL_PATH) -DDOC_PATH=$(DOC_PATH) -DBIN_PATH=$(BIN_PATH) $@.c network/*.c -o $@ $(LDFLAGS) $(INCLUDE) 

interceptor: interceptor.c $(COMM_HEADER)
	$(CC) -g $@.c network/state.c network/utilities.c -o $@ -lpcap

lib: afl-fuzz.c $(COMM_HEADER)
	$(CC) -Wl,--export-dynamic -c -DAFL_PATH=$(AFL_PATH) -DDOC_PATH=$(DOC_PATH) -DBIN_PATH=$(BIN_PATH) -fpic -DAFL_LIB=1 afl-fuzz.c
	$(CC) -shared -o libafl.so afl-fuzz.o
	rm afl-fuzz.o

afl-protocol: afl-protocol.c $(COMM_HEADER)
	$(CC) -L. -Wl,-rpath,. -o $@ $@.c -lafl -ldl

clean:
	rm -f afl-fuzz interceptor
	rm -f libafl.so
	rm -f afl-protocol
