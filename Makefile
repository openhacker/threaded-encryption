CC=gcc
# OPT= -O2
CFLAGS=-pthread -Wall -g ${OPT} 


all: 	threads

threads:	threads.o encrypt.o
	${CC} -pthread  $^ -o $@ -lcrypto

clean:
	rm threads
	rm *.o
