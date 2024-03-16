CC=gcc
CFLAGS=-pthread -Wall -g -O2


all: 	threads

threads:	threads.o encrypt.o
	${CC} -pthread  $^ -o $@ -lcrypto

clean:
	rm threads
