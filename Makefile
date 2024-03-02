

all: 	threads

threads:	threads.c
	${CC} -pthread -Wall -g $^ -o $@ -lcrypto

clean:
	rm threads
