libpatched:
	$(CC) -c -fPIC network.c -o network.o -ldl
	$(CC) -shared network.o -o libpatched.so -ldl

clean:
	rm -rf *.o *.so
