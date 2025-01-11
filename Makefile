CC = gcc
LIBS = -lpcap
CFLAGS = -g -Wall -pedantic -std=gnu99

all:  trace

trace: trace.c checksum.c
	$(CC) $(CFLAGS) -o $@ trace.c checksum.c $(LIBS)

run: trace
	./trace

clean:
	rm -f trace
