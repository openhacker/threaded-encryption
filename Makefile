
threads:	threads.c
	${CC} -pthread -g $^ -o $@
