
threads:	threads.c
	${CC} -pthread -Wall -g $^ -o $@ -lcrypto
