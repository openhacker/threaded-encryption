# -DZERO_IV -- use a zero IV all the time
#  -DSAVE_IV -- save IV in file (needed for random IV)
# use XCFLAGS or DEFINE for this
DEFINES += -DSAVE_IV
# DEFINES +=-DZERO_IV
CC=gcc
OPT= -O2
ifdef LOCAL_SSL
OPENSSL:=/usr/local/src/consulting/michael-lawrence/github.com/openssl
INCLUDES:=-I$(OPENSSL)/include
#LIBS:= -L$(OPENSSL) -Wl,--rpath=$(OPENSSL) -lcrypto
LIBS:= -L$(OPENSSL)  -l:libcrypto.a -ldl
else
LIBS=-lcrypto
endif



CFLAGS=-pthread -Wall -g ${OPT}  ${XCFLAGS} ${DEFINES} ${INCLUDES}


PROGS=encrypt-one  decrypt-one   zero_files  encrypt_files clear-cache
all: ${PROGS}

threads:	threads.o encrypt.o
	${CC} -pthread  $^ -o $@ ${LIBS} 

encrypt-one:	encrypt-one.o encrypt.o buffer_manager.o
	${CC} -pthread $^ -o $@ ${LIBS} 


decrypt-one:	decrypt-one.o encrypt.o buffer_manager.o
	${CC}  -pthread  $^ -o $@ ${LIBS} 

zero_files:	zero_files.o openssl_threads.o encrypt.o buffer_manager.o
	${CC} -pthread  $^ -o $@ ${LIBS} 

encrypt_files:	encrypt_files.o openssl_threads.o encrypt.o buffer_manager.o
	${CC}  -pthread $^ -o $@ ${LIBS} 


clear-cache:	clear-cache.c

suid:	clear-cache
	sudo chown root $^
	sudo chmod 4755 $^


clean:
	-rm  ${PROGS}
	-rm *.o
