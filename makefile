CC = gcc
CFLAGS = -O3 -Wall

all:
	mkdir -p builds
	$(CC) $(CFLAGS) -fPIC -o builds/base64.o -c src/base64.c
	$(CC) $(CFLAGS) -fPIC -o builds/sha512.o -c src/sha512.c
	$(CC) $(CFLAGS) -fPIC -o builds/xhash.o -c src/xhash.c
	ar rcs builds/libxhash.a builds/*.o
	#$(CC) -shared -o builds/libxhash.so builds/*.o
	$(CC) $(CFLAGS) -o builds/test test/test.c -lxhash -Lbuilds/ -Isrc/

clean:
	mkdir -p builds
	rm builds/*
