all: libhook

libhook: hook/hook.c
	$(CC) -c -fpic hook/hook.c -ldl
	$(CC) -shared -o libhook.so hook.o -ldl
	rm hook.o

clean:
	rm -f libhook.so

