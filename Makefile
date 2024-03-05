

all: 	threads

threads:	threads.c
	${CC} -pthread -Wall -g -O2 $^ -o $@ -lcrypto

clean:
	rm threads
