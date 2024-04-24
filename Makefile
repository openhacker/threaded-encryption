# -DZERO_IV -- use a zero IV all the time
#  -DSAVE_IV -- save IV in file (needed for random IV)
# use XCFLAGS or DEFINE for this
DEFINES += -DSAVE_IV
# 1M buffer
DEFINES += "-DBUFFER_SIZE=(64 * 1024)"
# DEFINES +=-DZERO_IV
CC=gcc
OPT= -O2
CFLAGS=-pthread -Wall -g ${OPT}  ${XCFLAGS} ${DEFINES}


PROGS=threads encrypt-one decrypt-one zero_files encrypt_files
all: ${PROGS}

threads:	threads.o encrypt.o
	${CC} -pthread  $^ -o $@ -lcrypto

encrypt-one:	encrypt-one.o encrypt.o
	${CC} -pthread  $^ -o $@ -lcrypto


decrypt-one:	decrypt-one.o encrypt.o
	${CC} -pthread  $^ -o $@ -lcrypto

zero_files:	zero_files.o openssl_threads.o encrypt.o
	${CC} -pthread $^ -o $@ -lcrypto

encrypt_files:	encrypt_files.o openssl_threads.o encrypt.o
	${CC} -pthread $^ -o $@ -lcrypto


clean:
	-rm  ${PROGS}
	-rm *.o
