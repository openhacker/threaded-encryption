CC=gcc
# OPT= -O2
CFLAGS=-pthread -Wall -g ${OPT}  ${XCFLAGS}


PROGS=threads encrypt-one decrypt-one
all: ${PROGS}

threads:	threads.o encrypt.o
	${CC} -pthread  $^ -o $@ -lcrypto

encrypt-one:	encrypt-one.o encrypt.o
	${CC} -pthread  $^ -o $@ -lcrypto


decrypt-one:	decrypt-one.o encrypt.o
	${CC} -pthread  $^ -o $@ -lcrypto

clean:
	-rm  ${PROGS}
	-rm *.o
