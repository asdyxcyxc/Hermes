all: libhook

libhook: hook.c
	$(CC) -c -fpic hook.c -ldl
	$(CC) -shared -o libhook.so hook.o -ldl
	rm hook.o

clean:
	rm -f libhook.so

